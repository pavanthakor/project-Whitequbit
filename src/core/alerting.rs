//! Operator Alerting and Visibility System
//!
//! Provides mechanisms for operators to:
//! - Receive critical alerts
//! - View system status
//! - Acknowledge failures
//! - Reset kill-switch
//!
//! # Alert Channels
//!
//! - File-based alerts (always available)
//! - Unix socket for real-time status
//! - Structured status reports

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info, warn};

use crate::core::failure::{
    FailureCategory, FailureRecord, FailureSeverity, KillSwitchState,
};

// ============================================================================
// Error Types
// ============================================================================

/// Errors from alerting operations
#[derive(Error, Debug)]
pub enum AlertError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Result type for alerting operations
pub type AlertResult<T> = Result<T, AlertError>;

// ============================================================================
// Alert Types
// ============================================================================

/// Priority level for alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertPriority {
    /// Informational
    Info,
    /// Warning - attention recommended
    Warning,
    /// Critical - immediate attention required
    Critical,
    /// Emergency - system security compromised
    Emergency,
}

impl From<FailureSeverity> for AlertPriority {
    fn from(severity: FailureSeverity) -> Self {
        match severity {
            FailureSeverity::Warning => AlertPriority::Warning,
            FailureSeverity::Error => AlertPriority::Warning,
            FailureSeverity::Critical => AlertPriority::Critical,
            FailureSeverity::Fatal => AlertPriority::Emergency,
        }
    }
}

/// An alert for operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub alert_id: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Priority
    pub priority: AlertPriority,
    /// Short title
    pub title: String,
    /// Detailed message
    pub message: String,
    /// Component that raised the alert
    pub component: String,
    /// Whether the alert has been acknowledged
    pub acknowledged: bool,
    /// Who acknowledged (if any)
    pub acknowledged_by: Option<String>,
    /// When acknowledged (if any)
    pub acknowledged_at: Option<DateTime<Utc>>,
    /// Related failure ID (if any)
    pub failure_id: Option<u64>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

impl Alert {
    /// Create a new alert
    pub fn new(
        alert_id: u64,
        priority: AlertPriority,
        title: impl Into<String>,
        message: impl Into<String>,
        component: impl Into<String>,
    ) -> Self {
        Self {
            alert_id,
            timestamp: Utc::now(),
            priority,
            title: title.into(),
            message: message.into(),
            component: component.into(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
            failure_id: None,
            recommended_actions: Vec::new(),
        }
    }

    /// Link to a failure
    pub fn with_failure(mut self, failure_id: u64) -> Self {
        self.failure_id = Some(failure_id);
        self
    }

    /// Add recommended action
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.recommended_actions.push(action.into());
        self
    }

    /// Create from a failure record
    pub fn from_failure(alert_id: u64, failure: &FailureRecord) -> Self {
        let priority = AlertPriority::from(failure.severity);

        let mut alert = Self::new(
            alert_id,
            priority,
            format!("{:?}: {}", failure.category, &failure.message),
            failure.details.clone().unwrap_or_default(),
            &failure.component,
        )
        .with_failure(failure.failure_id);

        // Add recommended actions based on failure type
        match failure.category {
            FailureCategory::RollbackFailed => {
                alert.recommended_actions.push(
                    "Check system state manually".to_string()
                );
                alert.recommended_actions.push(
                    "Review rollback logs".to_string()
                );
            }
            FailureCategory::ConfigurationInvalid => {
                alert.recommended_actions.push(
                    "Review configuration file".to_string()
                );
                alert.recommended_actions.push(
                    "Restore from backup if available".to_string()
                );
            }
            FailureCategory::SecurityViolation => {
                alert.recommended_actions.push(
                    "Review audit logs immediately".to_string()
                );
                alert.recommended_actions.push(
                    "Check for unauthorized access".to_string()
                );
            }
            _ => {}
        }

        alert
    }
}

// ============================================================================
// Agent Status
// ============================================================================

/// Current agent health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Operating normally
    Healthy,
    /// Degraded but operational
    Degraded,
    /// Not accepting new actions
    Blocked,
    /// Requires operator intervention
    Critical,
    /// Agent is offline
    Offline,
}

/// Comprehensive agent status for operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    /// Timestamp of this status
    pub timestamp: DateTime<Utc>,
    /// Overall health
    pub health: HealthStatus,
    /// Human-readable status message
    pub message: String,
    /// Kill-switch state
    pub kill_switch: KillSwitchState,
    /// Number of pending actions
    pub pending_actions: usize,
    /// Number of in-flight actions
    pub in_flight_actions: usize,
    /// Number of unacknowledged alerts
    pub unacked_alerts: usize,
    /// Recent failure count (last hour)
    pub recent_failures: usize,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Last successful action timestamp
    pub last_action_at: Option<DateTime<Utc>>,
    /// Configuration status
    pub config_status: ConfigStatus,
}

/// Configuration status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigStatus {
    /// Whether using primary config
    pub using_primary: bool,
    /// Whether using fallback config
    pub using_fallback: bool,
    /// Config file checksum
    pub checksum: Option<String>,
    /// Last loaded timestamp
    pub loaded_at: Option<DateTime<Utc>>,
    /// Validation warnings
    pub warnings: Vec<String>,
}

impl Default for ConfigStatus {
    fn default() -> Self {
        Self {
            using_primary: true,
            using_fallback: false,
            checksum: None,
            loaded_at: None,
            warnings: Vec::new(),
        }
    }
}

// ============================================================================
// Alert Manager
// ============================================================================

/// Manages alerts and operator visibility
pub struct AlertManager {
    /// Alert storage
    alerts: RwLock<VecDeque<Alert>>,
    /// Maximum alerts to keep
    max_alerts: usize,
    /// Next alert ID
    next_id: std::sync::atomic::AtomicU64,
    /// Alert file path
    alert_path: PathBuf,
    /// Status file path
    status_path: PathBuf,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        let base = base_path.as_ref();
        Self {
            alerts: RwLock::new(VecDeque::with_capacity(1000)),
            max_alerts: 1000,
            next_id: std::sync::atomic::AtomicU64::new(1),
            alert_path: base.join("alerts.jsonl"),
            status_path: base.join("status.json"),
        }
    }

    /// Raise a new alert
    pub fn raise_alert(&self, mut alert: Alert) -> AlertResult<u64> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        alert.alert_id = id;

        // Log based on priority
        match alert.priority {
            AlertPriority::Emergency => {
                error!("EMERGENCY ALERT: {} - {}", alert.title, alert.message);
            }
            AlertPriority::Critical => {
                error!("CRITICAL ALERT: {} - {}", alert.title, alert.message);
            }
            AlertPriority::Warning => {
                warn!("ALERT: {} - {}", alert.title, alert.message);
            }
            AlertPriority::Info => {
                info!("ALERT: {} - {}", alert.title, alert.message);
            }
        }

        // Add to in-memory store
        {
            let mut alerts = self.alerts.write().unwrap();
            alerts.push_back(alert.clone());
            while alerts.len() > self.max_alerts {
                alerts.pop_front();
            }
        }

        // Persist to file
        self.persist_alert(&alert)?;

        Ok(id)
    }

    /// Raise an alert from a failure record
    pub fn alert_from_failure(&self, failure: &FailureRecord) -> AlertResult<u64> {
        let alert_id = self.next_id.load(std::sync::atomic::Ordering::SeqCst);
        let alert = Alert::from_failure(alert_id, failure);
        self.raise_alert(alert)
    }

    /// Persist alert to file
    fn persist_alert(&self, alert: &Alert) -> AlertResult<()> {
        if let Some(parent) = self.alert_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.alert_path)?;

        let line = serde_json::to_string(alert)
            .map_err(|e| AlertError::Serialization(e.to_string()))?;

        writeln!(file, "{}", line)?;
        file.sync_all()?;

        Ok(())
    }

    /// Acknowledge an alert
    pub fn acknowledge(&self, alert_id: u64, operator: impl Into<String>) -> bool {
        let operator = operator.into();

        let mut alerts = self.alerts.write().unwrap();
        for alert in alerts.iter_mut() {
            if alert.alert_id == alert_id {
                alert.acknowledged = true;
                alert.acknowledged_by = Some(operator);
                alert.acknowledged_at = Some(Utc::now());
                return true;
            }
        }

        false
    }

    /// Get all unacknowledged alerts
    pub fn unacknowledged(&self) -> Vec<Alert> {
        self.alerts
            .read()
            .unwrap()
            .iter()
            .filter(|a| !a.acknowledged)
            .cloned()
            .collect()
    }

    /// Get alerts by priority
    pub fn by_priority(&self, priority: AlertPriority) -> Vec<Alert> {
        self.alerts
            .read()
            .unwrap()
            .iter()
            .filter(|a| a.priority >= priority)
            .cloned()
            .collect()
    }

    /// Get recent alerts
    pub fn recent(&self, count: usize) -> Vec<Alert> {
        let alerts = self.alerts.read().unwrap();
        alerts.iter().rev().take(count).cloned().collect()
    }

    /// Write status to file
    pub fn write_status(&self, status: &AgentStatus) -> AlertResult<()> {
        if let Some(parent) = self.status_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(status)
            .map_err(|e| AlertError::Serialization(e.to_string()))?;

        let tmp_path = self.status_path.with_extension("tmp");
        fs::write(&tmp_path, content)?;
        fs::rename(&tmp_path, &self.status_path)?;

        Ok(())
    }

    /// Get count of unacknowledged alerts
    pub fn unacked_count(&self) -> usize {
        self.alerts
            .read()
            .unwrap()
            .iter()
            .filter(|a| !a.acknowledged)
            .count()
    }
}

// ============================================================================
// Status Reporter
// ============================================================================

/// Generates status reports
pub struct StatusReporter {
    /// Alert manager reference
    alert_manager: Arc<AlertManager>,
    /// Start time for uptime calculation
    start_time: std::time::Instant,
}

impl StatusReporter {
    /// Create a new status reporter
    pub fn new(alert_manager: Arc<AlertManager>) -> Self {
        Self {
            alert_manager,
            start_time: std::time::Instant::now(),
        }
    }

    /// Generate current status
    pub fn generate_status(
        &self,
        kill_switch: &KillSwitchState,
        pending_actions: usize,
        in_flight_actions: usize,
        recent_failures: usize,
        last_action_at: Option<DateTime<Utc>>,
        config_status: ConfigStatus,
    ) -> AgentStatus {
        let unacked = self.alert_manager.unacked_count();

        // Determine overall health
        let health = if kill_switch.active {
            HealthStatus::Critical
        } else if unacked > 0 || recent_failures > 5 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        let message = match health {
            HealthStatus::Healthy => "Agent operating normally".to_string(),
            HealthStatus::Degraded => format!(
                "Degraded: {} unacked alerts, {} recent failures",
                unacked, recent_failures
            ),
            HealthStatus::Blocked => "Agent is blocking new actions".to_string(),
            HealthStatus::Critical => {
                format!(
                    "CRITICAL: Kill-switch active - {}",
                    kill_switch.reason.as_deref().unwrap_or("unknown reason")
                )
            }
            HealthStatus::Offline => "Agent is offline".to_string(),
        };

        AgentStatus {
            timestamp: Utc::now(),
            health,
            message,
            kill_switch: kill_switch.clone(),
            pending_actions,
            in_flight_actions,
            unacked_alerts: unacked,
            recent_failures,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            last_action_at,
            config_status,
        }
    }
}

// ============================================================================
// Intervention Request
// ============================================================================

/// Request for operator intervention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterventionRequest {
    /// Request ID
    pub request_id: u64,
    /// When requested
    pub requested_at: DateTime<Utc>,
    /// Type of intervention needed
    pub intervention_type: InterventionType,
    /// Description
    pub description: String,
    /// Related alert IDs
    pub related_alerts: Vec<u64>,
    /// Related failure IDs
    pub related_failures: Vec<u64>,
    /// Steps for operator
    pub steps: Vec<String>,
    /// Whether resolved
    pub resolved: bool,
    /// Resolution notes
    pub resolution_notes: Option<String>,
}

/// Type of intervention required
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionType {
    /// Acknowledge kill-switch
    AcknowledgeKillSwitch,
    /// Manual rollback required
    ManualRollback,
    /// Configuration repair
    ConfigRepair,
    /// Security review
    SecurityReview,
    /// System recovery
    SystemRecovery,
    /// Other
    Other,
}

impl InterventionRequest {
    /// Create a new intervention request
    pub fn new(
        request_id: u64,
        intervention_type: InterventionType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            request_id,
            requested_at: Utc::now(),
            intervention_type,
            description: description.into(),
            related_alerts: Vec::new(),
            related_failures: Vec::new(),
            steps: Vec::new(),
            resolved: false,
            resolution_notes: None,
        }
    }

    /// Add a step
    pub fn with_step(mut self, step: impl Into<String>) -> Self {
        self.steps.push(step.into());
        self
    }

    /// Link to alert
    pub fn with_alert(mut self, alert_id: u64) -> Self {
        self.related_alerts.push(alert_id);
        self
    }

    /// Link to failure
    pub fn with_failure(mut self, failure_id: u64) -> Self {
        self.related_failures.push(failure_id);
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_alert_creation() {
        let alert = Alert::new(
            1,
            AlertPriority::Critical,
            "Test Alert",
            "This is a test",
            "test_component",
        )
        .with_failure(42)
        .with_action("Check logs");

        assert_eq!(alert.alert_id, 1);
        assert_eq!(alert.priority, AlertPriority::Critical);
        assert_eq!(alert.failure_id, Some(42));
        assert!(!alert.acknowledged);
    }

    #[test]
    fn test_alert_from_failure() {
        let failure = FailureRecord::new(
            1,
            FailureCategory::RollbackFailed,
            FailureSeverity::Critical,
            "Rollback failed",
            "compensator",
        );

        let alert = Alert::from_failure(1, &failure);

        assert_eq!(alert.priority, AlertPriority::Critical);
        assert_eq!(alert.failure_id, Some(1));
        assert!(!alert.recommended_actions.is_empty());
    }

    #[test]
    fn test_alert_manager() {
        let dir = TempDir::new().unwrap();
        let manager = AlertManager::new(dir.path());

        // Raise alert
        let alert = Alert::new(
            0, // Will be assigned
            AlertPriority::Warning,
            "Test",
            "Message",
            "test",
        );

        let id = manager.raise_alert(alert).unwrap();
        assert!(id > 0);

        // Check unacknowledged
        let unacked = manager.unacknowledged();
        assert_eq!(unacked.len(), 1);

        // Acknowledge
        assert!(manager.acknowledge(id, "operator@example.com"));

        // Now should be empty
        let unacked = manager.unacknowledged();
        assert!(unacked.is_empty());
    }

    #[test]
    fn test_intervention_request() {
        let request = InterventionRequest::new(
            1,
            InterventionType::ManualRollback,
            "Rollback failed, manual intervention needed",
        )
        .with_step("SSH to server")
        .with_step("Check firewall state: iptables -L")
        .with_step("Restore from backup if needed")
        .with_failure(42);

        assert_eq!(request.steps.len(), 3);
        assert!(!request.resolved);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(AlertPriority::Emergency > AlertPriority::Critical);
        assert!(AlertPriority::Critical > AlertPriority::Warning);
        assert!(AlertPriority::Warning > AlertPriority::Info);
    }
}
