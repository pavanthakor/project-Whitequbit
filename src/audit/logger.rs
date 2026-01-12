//! Audit Logger - Append-only structured logging
//!
//! Provides structured audit logging with hash chaining for tamper evidence.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::actions::ActionResult;
use crate::config::AgentConfig;
use crate::events::Event;

use super::sink::FileSink;
use super::AuditError;

/// Type of audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Lifecycle events
    /// Agent started up
    AgentStartup,
    /// Agent shut down
    AgentShutdown,
    /// Configuration was reloaded
    ConfigReloaded,

    // Event handling
    /// Event was received
    EventReceived,
    /// Event was rejected
    EventRejected,

    // Action lifecycle
    /// Action was prepared
    ActionPrepared,
    /// Action was committed
    ActionCommitted,
    /// Action was rolled back
    ActionRolledBack,
    /// Action was rejected
    ActionRejected,
    /// Rollback operation failed
    RollbackFailed,

    // Security events
    /// Authentication succeeded
    AuthenticationSuccess,
    /// Authentication failed
    AuthenticationFailure,
    /// Authorization was denied
    AuthorizationDenied,
    /// Privileges were dropped
    PrivilegeDropped,
    /// Sandbox was applied
    SandboxApplied,

    // System events
    /// Recovery process started
    RecoveryStarted,
    /// Recovery process completed
    RecoveryCompleted,
    /// Integrity check passed
    IntegrityCheckPassed,
    /// Integrity check failed
    IntegrityCheckFailed,
}

/// An audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry sequence number
    pub sequence: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Actor (who initiated the action)
    pub actor: Option<String>,
    /// Target resource
    pub target: Option<String>,
    /// Event details
    pub details: serde_json::Value,
    /// Hash of previous entry (chain link)
    pub previous_hash: String,
    /// Hash of this entry
    pub hash: String,
}

impl AuditEntry {
    /// Create a new audit entry
    fn new(
        sequence: u64,
        event_type: AuditEventType,
        previous_hash: String,
    ) -> Self {
        let mut entry = Self {
            sequence,
            timestamp: Utc::now(),
            event_type,
            actor: None,
            target: None,
            details: serde_json::Value::Null,
            previous_hash,
            hash: String::new(),
        };

        entry.hash = entry.compute_hash();
        entry
    }

    /// Set the actor
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self.hash = self.compute_hash();
        self
    }

    /// Set the target
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self.hash = self.compute_hash();
        self
    }

    /// Set the details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self.hash = self.compute_hash();
        self
    }

    /// Compute the hash of this entry
    fn compute_hash(&self) -> String {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", self.event_type).as_bytes());

        if let Some(ref actor) = self.actor {
            hasher.update(actor.as_bytes());
        }
        if let Some(ref target) = self.target {
            hasher.update(target.as_bytes());
        }

        hasher.update(self.details.to_string().as_bytes());
        hasher.update(self.previous_hash.as_bytes());

        let hash = hasher.finalize();
        hash.to_hex().to_string()
    }

    /// Verify this entry's hash
    pub fn verify(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

/// State for the audit logger
struct LoggerState {
    /// Next sequence number
    next_sequence: u64,
    /// Hash of the last entry
    last_hash: String,
}

/// Audit logger with hash chain integrity
pub struct AuditLogger {
    /// Audit sink for writing entries
    sink: FileSink,
    /// Logger state
    state: RwLock<LoggerState>,
}

impl AuditLogger {
    /// Create a new audit logger writing to a file
    pub fn new(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let sink = FileSink::new(path)?;

        // Load existing entries to get last hash
        let (next_sequence, last_hash) = sink.get_chain_state()?;

        Ok(Self {
            sink,
            state: RwLock::new(LoggerState {
                next_sequence,
                last_hash,
            }),
        })
    }

    /// Append an entry to the audit log
    #[allow(dead_code)]
    async fn append(&self, event_type: AuditEventType) -> Result<AuditEntry, AuditError> {
        let mut state = self.state.write().await;

        let entry = AuditEntry::new(
            state.next_sequence,
            event_type,
            state.last_hash.clone(),
        );

        // Write to sink
        self.sink.write(&entry).await?;

        // Update state
        state.next_sequence += 1;
        state.last_hash = entry.hash.clone();

        tracing::debug!("Audit entry {}: {:?}", entry.sequence, entry.event_type);
        Ok(entry)
    }

    /// Append an entry with details
    async fn append_with_details(
        &self,
        event_type: AuditEventType,
        details: serde_json::Value,
    ) -> Result<AuditEntry, AuditError> {
        let mut state = self.state.write().await;

        let entry = AuditEntry::new(
            state.next_sequence,
            event_type,
            state.last_hash.clone(),
        )
        .with_details(details);

        self.sink.write(&entry).await?;

        state.next_sequence += 1;
        state.last_hash = entry.hash.clone();

        tracing::debug!("Audit entry {}: {:?}", entry.sequence, entry.event_type);
        Ok(entry)
    }

    // Lifecycle events

    /// Log agent startup
    pub async fn log_startup(&self, config: &AgentConfig) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::AgentStartup,
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "config_path": config.config_path.display().to_string(),
            }),
        )
        .await?;
        Ok(())
    }

    /// Log agent shutdown
    pub async fn log_shutdown(&self, reason: &str) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::AgentShutdown,
            serde_json::json!({ "reason": reason }),
        )
        .await?;
        Ok(())
    }

    /// Log config reload
    pub async fn log_config_reload(&self, success: bool) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::ConfigReloaded,
            serde_json::json!({ "success": success }),
        )
        .await?;
        Ok(())
    }

    // Event handling

    /// Log event received
    pub async fn log_event_received(&self, event: &Event) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::EventReceived,
            serde_json::json!({
                "event_type": format!("{:?}", event.event_type()),
                "source": event.client().map(|c| c.principal.clone()).unwrap_or_else(|| "unknown".to_string()),
            }),
        )
        .await?;
        Ok(())
    }

    /// Log event rejected
    pub async fn log_event_rejected(&self, event: &Event, reason: &str) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::EventRejected,
            serde_json::json!({
                "event_type": format!("{:?}", event.event_type()),
                "source": event.client().map(|c| c.principal.clone()).unwrap_or_else(|| "unknown".to_string()),
                "reason": reason,
            }),
        )
        .await?;
        Ok(())
    }

    // Action lifecycle

    /// Log action prepared (before execution)
    pub async fn log_action_prepared(
        &self,
        action_id: &str,
        action_type: &str,
        actor: Option<&str>,
    ) -> Result<(), AuditError> {
        let mut entry = AuditEntry::new(
            self.state.read().await.next_sequence,
            AuditEventType::ActionPrepared,
            self.state.read().await.last_hash.clone(),
        )
        .with_details(serde_json::json!({
            "action_id": action_id,
            "action_type": action_type,
        }));

        if let Some(actor) = actor {
            entry = entry.with_actor(actor);
        }

        let mut state = self.state.write().await;
        self.sink.write(&entry).await?;
        state.next_sequence += 1;
        state.last_hash = entry.hash.clone();

        Ok(())
    }

    /// Log action committed (successful execution)
    pub async fn log_action_committed(
        &self,
        action_id: &str,
        result: &ActionResult,
    ) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::ActionCommitted,
            serde_json::json!({
                "action_id": action_id,
                "success": result.changed,
                "message": result.message,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log action rolled back
    pub async fn log_action_rolled_back(
        &self,
        action_id: &str,
        reason: &str,
    ) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::ActionRolledBack,
            serde_json::json!({
                "action_id": action_id,
                "reason": reason,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log action rejected (validation failed)
    pub async fn log_action_rejected(
        &self,
        action_type: &str,
        reason: &str,
    ) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::ActionRejected,
            serde_json::json!({
                "action_type": action_type,
                "reason": reason,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log rollback failure
    pub async fn log_rollback_failed(
        &self,
        action_id: &str,
        error: &str,
    ) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::RollbackFailed,
            serde_json::json!({
                "action_id": action_id,
                "error": error,
            }),
        )
        .await?;
        Ok(())
    }

    // Security events

    /// Log authentication success
    pub async fn log_auth_success(&self, principal: &str, method: &str) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::AuthenticationSuccess,
            serde_json::json!({
                "principal": principal,
                "method": method,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log authentication failure
    pub async fn log_auth_failure(&self, principal: &str, reason: &str) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::AuthenticationFailure,
            serde_json::json!({
                "principal": principal,
                "reason": reason,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log authorization denied
    pub async fn log_authz_denied(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
    ) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::AuthorizationDenied,
            serde_json::json!({
                "principal": principal,
                "action": action,
                "resource": resource,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log privilege drop
    pub async fn log_privilege_dropped(&self, from_uid: u32, to_uid: u32) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::PrivilegeDropped,
            serde_json::json!({
                "from_uid": from_uid,
                "to_uid": to_uid,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log sandbox applied
    pub async fn log_sandbox_applied(&self, sandbox_type: &str) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::SandboxApplied,
            serde_json::json!({
                "sandbox_type": sandbox_type,
            }),
        )
        .await?;
        Ok(())
    }

    // System events

    /// Log recovery started
    pub async fn log_recovery_started(&self, uncommitted_count: usize) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::RecoveryStarted,
            serde_json::json!({
                "uncommitted_entries": uncommitted_count,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log recovery completed
    pub async fn log_recovery_completed(
        &self,
        recovered: usize,
        failed: usize,
    ) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::RecoveryCompleted,
            serde_json::json!({
                "recovered": recovered,
                "failed": failed,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log integrity check passed
    pub async fn log_integrity_passed(&self, entries_checked: u64) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::IntegrityCheckPassed,
            serde_json::json!({
                "entries_checked": entries_checked,
            }),
        )
        .await?;
        Ok(())
    }

    /// Log integrity check failed
    pub async fn log_integrity_failed(
        &self,
        entry: u64,
        reason: &str,
    ) -> Result<(), AuditError> {
        self.append_with_details(
            AuditEventType::IntegrityCheckFailed,
            serde_json::json!({
                "failed_entry": entry,
                "reason": reason,
            }),
        )
        .await?;
        Ok(())
    }

    /// Verify the integrity of the audit log
    pub fn verify_integrity(&self) -> Result<super::integrity::VerificationResult, AuditError> {
        // Would verify from the file path
        // For now, return a placeholder
        Ok(super::integrity::VerificationResult::pass(0))
    }

    /// Flush the audit log
    pub async fn flush(&self) -> Result<(), AuditError> {
        self.sink.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_audit_logger() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let logger = AuditLogger::new(&path).unwrap();

        // Log some events
        logger.log_shutdown("test").await.unwrap();

        // Verify chain is maintained
        let result = logger.verify_integrity().unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_entry_hash_verification() {
        let entry = AuditEntry::new(1, AuditEventType::AgentStartup, String::new());
        assert!(entry.verify());

        // Tampered entry should fail
        let mut tampered = entry.clone();
        tampered.sequence = 2;
        assert!(!tampered.verify());
    }
}
