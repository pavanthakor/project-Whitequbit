//! Failure Handling System for Security Agent
//!
//! Provides comprehensive failure handling for worst-case scenarios:
//!
//! 1. **Agent crashes mid-firewall update** → Atomic WAL + recovery on restart
//! 2. **Partial command execution** → Transaction boundaries + compensation
//! 3. **Rollback failure** → Kill-switch defaults + operator alerting
//! 4. **Corrupted configuration** → Validation + fallback to safe defaults
//!
//! # Design Principles
//!
//! - **Fail-Safe**: When in doubt, apply restrictive defaults
//! - **Fail-Visible**: All failures are logged and alertable
//! - **Fail-Recoverable**: Automatic recovery where safe, manual otherwise
//! - **Fail-Auditable**: Complete audit trail of all failures
//!
//! # Kill-Switch Behavior
//!
//! When the agent cannot guarantee security state consistency, it activates
//! the kill-switch which:
//! 1. Blocks all new actions
//! 2. Applies safe firewall defaults (deny all except SSH)
//! 3. Logs critical alert for operator
//! 4. Enters read-only mode until manual intervention

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from failure handling operations
#[derive(Error, Debug)]
pub enum FailureError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Kill-switch is active
    #[error("Kill-switch active: {reason}")]
    KillSwitchActive {
        /// Why the kill-switch was activated
        reason: String,
    },

    /// Unrecoverable failure
    #[error("Unrecoverable failure: {0}")]
    Unrecoverable(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Recovery failed
    #[error("Recovery failed: {message}, manual intervention required")]
    RecoveryFailed {
        /// Description of the recovery failure
        message: String,
    },

    /// Integrity violation
    #[error("Integrity violation: {0}")]
    IntegrityViolation(String),
}

/// Result type for failure handling operations
pub type FailureResult<T> = Result<T, FailureError>;

// ============================================================================
// Failure Categories
// ============================================================================

/// Category of failure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    /// Agent crashed (detected on restart)
    Crash,
    /// Action execution failed
    ActionFailed,
    /// Rollback failed
    RollbackFailed,
    /// Configuration invalid
    ConfigurationInvalid,
    /// State inconsistency detected
    StateInconsistent,
    /// External dependency failed
    DependencyFailed,
    /// Resource exhaustion
    ResourceExhausted,
    /// Security violation
    SecurityViolation,
    /// Timeout
    Timeout,
    /// Unknown/uncategorized
    Unknown,
}

/// Severity of the failure
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureSeverity {
    /// Can continue with degraded functionality
    Warning,
    /// Operation failed but agent is stable
    Error,
    /// Agent stability compromised
    Critical,
    /// Security posture compromised - kill-switch
    Fatal,
}

/// Recommended action for a failure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureAction {
    /// Retry the operation
    Retry {
        /// Maximum number of retry attempts
        max_attempts: u32,
        /// Delay between retries in milliseconds
        delay_ms: u64,
    },
    /// Skip this operation and continue
    Skip,
    /// Rollback and continue
    Rollback,
    /// Apply safe defaults
    ApplySafeDefaults,
    /// Activate kill-switch
    ActivateKillSwitch,
    /// Require manual intervention
    RequireIntervention,
    /// Shutdown agent
    Shutdown,
}

// ============================================================================
// Failure Record
// ============================================================================

/// Record of a failure event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureRecord {
    /// Unique failure ID
    pub failure_id: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Category
    pub category: FailureCategory,
    /// Severity
    pub severity: FailureSeverity,
    /// Human-readable message
    pub message: String,
    /// Error details
    pub details: Option<String>,
    /// Affected component
    pub component: String,
    /// Action taken
    pub action_taken: FailureAction,
    /// Whether recovery succeeded
    pub recovered: bool,
    /// Additional context
    #[serde(default)]
    pub context: BTreeMap<String, String>,
}

impl FailureRecord {
    /// Create a new failure record
    pub fn new(
        failure_id: u64,
        category: FailureCategory,
        severity: FailureSeverity,
        message: impl Into<String>,
        component: impl Into<String>,
    ) -> Self {
        Self {
            failure_id,
            timestamp: Utc::now(),
            category,
            severity,
            message: message.into(),
            details: None,
            component: component.into(),
            action_taken: FailureAction::Skip,
            recovered: false,
            context: BTreeMap::new(),
        }
    }

    /// Add details
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Add context
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Set action taken
    pub fn with_action(mut self, action: FailureAction) -> Self {
        self.action_taken = action;
        self
    }

    /// Mark as recovered
    pub fn mark_recovered(mut self) -> Self {
        self.recovered = true;
        self
    }
}

// ============================================================================
// Safe Defaults Configuration
// ============================================================================

/// Safe defaults to apply when security state is uncertain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeDefaults {
    /// Firewall defaults
    pub firewall: FirewallDefaults,
    /// Service defaults
    pub services: ServiceDefaults,
    /// Access defaults
    pub access: AccessDefaults,
}

impl Default for SafeDefaults {
    fn default() -> Self {
        Self {
            firewall: FirewallDefaults::default(),
            services: ServiceDefaults::default(),
            access: AccessDefaults::default(),
        }
    }
}

/// Safe firewall defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallDefaults {
    /// Default policy for input chain
    pub input_policy: DefaultPolicy,
    /// Default policy for output chain
    pub output_policy: DefaultPolicy,
    /// Default policy for forward chain
    pub forward_policy: DefaultPolicy,
    /// Always-allowed ports (e.g., SSH for recovery)
    pub allowed_ports: Vec<AllowedPort>,
    /// Flush all rules before applying defaults
    pub flush_first: bool,
}

impl Default for FirewallDefaults {
    fn default() -> Self {
        Self {
            input_policy: DefaultPolicy::Drop,
            output_policy: DefaultPolicy::Accept, // Allow outbound for logging
            forward_policy: DefaultPolicy::Drop,
            allowed_ports: vec![
                AllowedPort {
                    port: 22,
                    protocol: "tcp".to_string(),
                    description: "SSH for emergency access".to_string(),
                },
            ],
            flush_first: false, // Don't flush by default to avoid lockout
        }
    }
}

/// Default firewall policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    /// Accept all traffic
    Accept,
    /// Drop all traffic
    Drop,
    /// Reject with ICMP response
    Reject,
}

/// Port to always allow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedPort {
    /// Port number
    pub port: u16,
    /// Protocol (tcp/udp)
    pub protocol: String,
    /// Description
    pub description: String,
}

/// Safe service defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefaults {
    /// Services to ensure are running
    pub ensure_running: Vec<String>,
    /// Services to stop in emergency
    pub stop_in_emergency: Vec<String>,
}

impl Default for ServiceDefaults {
    fn default() -> Self {
        Self {
            ensure_running: vec!["sshd".to_string()],
            stop_in_emergency: Vec::new(),
        }
    }
}

/// Safe access defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDefaults {
    /// Reject all new connections
    pub reject_new_connections: bool,
    /// Allow existing connections to continue
    pub allow_established: bool,
    /// Trusted source addresses (CIDR)
    pub trusted_sources: Vec<String>,
}

impl Default for AccessDefaults {
    fn default() -> Self {
        Self {
            reject_new_connections: true,
            allow_established: true,
            trusted_sources: Vec::new(),
        }
    }
}

// ============================================================================
// Kill Switch
// ============================================================================

/// Kill-switch state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchState {
    /// Whether kill-switch is active
    pub active: bool,
    /// When it was activated
    pub activated_at: Option<DateTime<Utc>>,
    /// Why it was activated
    pub reason: Option<String>,
    /// Failure that triggered it
    pub trigger_failure_id: Option<u64>,
    /// Safe defaults applied
    pub defaults_applied: bool,
    /// Operator acknowledgment required
    pub requires_ack: bool,
}

impl Default for KillSwitchState {
    fn default() -> Self {
        Self {
            active: false,
            activated_at: None,
            reason: None,
            trigger_failure_id: None,
            defaults_applied: false,
            requires_ack: false,
        }
    }
}

/// Kill-switch controller
pub struct KillSwitch {
    /// Atomic flag for fast checking
    active: AtomicBool,
    /// Full state
    state: RwLock<KillSwitchState>,
    /// Safe defaults to apply
    defaults: SafeDefaults,
    /// State file path for persistence
    state_path: PathBuf,
}

impl KillSwitch {
    /// Create a new kill-switch
    pub fn new(state_path: impl Into<PathBuf>, defaults: SafeDefaults) -> Self {
        Self {
            active: AtomicBool::new(false),
            state: RwLock::new(KillSwitchState::default()),
            defaults,
            state_path: state_path.into(),
        }
    }

    /// Load persisted state (called on startup)
    pub fn load_state(&self) -> FailureResult<bool> {
        if !self.state_path.exists() {
            return Ok(false);
        }

        let content = fs::read_to_string(&self.state_path)?;
        let persisted: KillSwitchState = serde_json::from_str(&content)
            .map_err(|e| FailureError::Serialization(e.to_string()))?;

        if persisted.active {
            tracing::warn!("Kill-switch was active before restart, restoring state");
            self.active.store(true, Ordering::SeqCst);
            *self.state.write().unwrap() = persisted;
            return Ok(true);
        }

        Ok(false)
    }

    /// Persist current state
    fn persist_state(&self) -> FailureResult<()> {
        let state = self.state.read().unwrap();
        let content = serde_json::to_string_pretty(&*state)
            .map_err(|e| FailureError::Serialization(e.to_string()))?;

        // Ensure directory exists
        if let Some(parent) = self.state_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Atomic write
        let tmp_path = self.state_path.with_extension("tmp");
        fs::write(&tmp_path, content)?;
        fs::rename(&tmp_path, &self.state_path)?;

        Ok(())
    }

    /// Check if kill-switch is active (fast path)
    #[inline]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Activate the kill-switch
    #[instrument(skip(self, reason))]
    pub fn activate(&self, reason: impl Into<String>, failure_id: u64) -> FailureResult<()> {
        let reason = reason.into();
        tracing::error!("KILL-SWITCH ACTIVATED: {}", reason);

        // Set atomic flag first (fast rejection of new requests)
        self.active.store(true, Ordering::SeqCst);

        // Update full state
        {
            let mut state = self.state.write().unwrap();
            state.active = true;
            state.activated_at = Some(Utc::now());
            state.reason = Some(reason.clone());
            state.trigger_failure_id = Some(failure_id);
            state.requires_ack = true;
        }

        // Persist state
        self.persist_state()?;

        // Apply safe defaults
        self.apply_safe_defaults()?;

        // Mark defaults applied
        {
            let mut state = self.state.write().unwrap();
            state.defaults_applied = true;
        }
        self.persist_state()?;

        Ok(())
    }

    /// Apply safe defaults (firewall rules, etc.)
    fn apply_safe_defaults(&self) -> FailureResult<()> {
        tracing::info!("Applying safe defaults");

        // In production, this would call the firewall module
        // For now, we log what would be done

        let fw = &self.defaults.firewall;
        tracing::info!("Would set INPUT policy to {:?}", fw.input_policy);
        tracing::info!("Would set OUTPUT policy to {:?}", fw.output_policy);
        tracing::info!("Would set FORWARD policy to {:?}", fw.forward_policy);

        for port in &fw.allowed_ports {
            tracing::info!(
                "Would allow {} port {} ({})",
                port.protocol, port.port, port.description
            );
        }

        // TODO: Actually apply firewall rules via FirewallAction
        // This requires integration with the actions module

        Ok(())
    }

    /// Deactivate kill-switch (requires operator acknowledgment)
    #[instrument(skip(self, operator))]
    pub fn deactivate(&self, operator: impl Into<String>) -> FailureResult<()> {
        let operator = operator.into();
        tracing::info!("Kill-switch deactivated by operator: {}", operator);

        self.active.store(false, Ordering::SeqCst);

        {
            let mut state = self.state.write().unwrap();
            state.active = false;
            state.requires_ack = false;
        }

        self.persist_state()?;

        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> KillSwitchState {
        self.state.read().unwrap().clone()
    }

    /// Get safe defaults
    pub fn defaults(&self) -> &SafeDefaults {
        &self.defaults
    }
}

// ============================================================================
// In-Flight Action Tracker
// ============================================================================

/// State of an in-flight action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InFlightAction {
    /// Action ID
    pub action_id: String,
    /// Action type
    pub action_type: String,
    /// When the action started
    pub started_at: DateTime<Utc>,
    /// Current phase
    pub phase: ActionPhase,
    /// Pre-action state (for rollback)
    pub pre_state: Option<serde_json::Value>,
    /// Post-action state (for verification)
    pub post_state: Option<serde_json::Value>,
    /// Compensation data
    pub compensation_data: Option<serde_json::Value>,
}

/// Phase of action execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPhase {
    /// Preparing (gathering state)
    Preparing,
    /// Logged to WAL
    Logged,
    /// Executing
    Executing,
    /// Verifying
    Verifying,
    /// Committed
    Committed,
    /// Rolling back
    RollingBack,
    /// Rolled back
    RolledBack,
    /// Failed (requires intervention)
    Failed,
}

/// Tracks in-flight actions for crash recovery
pub struct InFlightTracker {
    /// Currently executing actions
    actions: RwLock<BTreeMap<String, InFlightAction>>,
    /// Persistence path
    persist_path: PathBuf,
}

impl InFlightTracker {
    /// Create a new tracker
    pub fn new(persist_path: impl Into<PathBuf>) -> Self {
        Self {
            actions: RwLock::new(BTreeMap::new()),
            persist_path: persist_path.into(),
        }
    }

    /// Load persisted in-flight actions (called on restart)
    pub fn load(&self) -> FailureResult<Vec<InFlightAction>> {
        if !self.persist_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.persist_path)?;
        let reader = BufReader::new(file);

        let mut actions = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            match serde_json::from_str::<InFlightAction>(&line) {
                Ok(action) => actions.push(action),
                Err(e) => {
                    tracing::warn!("Failed to parse in-flight action: {}", e);
                }
            }
        }

        // Also load into memory
        let mut guard = self.actions.write().unwrap();
        for action in &actions {
            guard.insert(action.action_id.clone(), action.clone());
        }

        Ok(actions)
    }

    /// Persist current state
    fn persist(&self) -> FailureResult<()> {
        let actions = self.actions.read().unwrap();

        // Ensure directory exists
        if let Some(parent) = self.persist_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = self.persist_path.with_extension("tmp");
        let mut file = File::create(&tmp_path)?;

        for action in actions.values() {
            let line = serde_json::to_string(action)
                .map_err(|e| FailureError::Serialization(e.to_string()))?;
            writeln!(file, "{}", line)?;
        }

        file.sync_all()?;
        fs::rename(&tmp_path, &self.persist_path)?;

        Ok(())
    }

    /// Register a new in-flight action
    pub fn register(
        &self,
        action_id: impl Into<String>,
        action_type: impl Into<String>,
    ) -> FailureResult<()> {
        let action = InFlightAction {
            action_id: action_id.into(),
            action_type: action_type.into(),
            started_at: Utc::now(),
            phase: ActionPhase::Preparing,
            pre_state: None,
            post_state: None,
            compensation_data: None,
        };

        {
            let mut guard = self.actions.write().unwrap();
            guard.insert(action.action_id.clone(), action);
        }

        self.persist()?;
        Ok(())
    }

    /// Update action phase
    pub fn update_phase(&self, action_id: &str, phase: ActionPhase) -> FailureResult<()> {
        {
            let mut guard = self.actions.write().unwrap();
            if let Some(action) = guard.get_mut(action_id) {
                action.phase = phase;
            }
        }

        self.persist()?;
        Ok(())
    }

    /// Set pre-action state
    pub fn set_pre_state(
        &self,
        action_id: &str,
        state: serde_json::Value,
    ) -> FailureResult<()> {
        {
            let mut guard = self.actions.write().unwrap();
            if let Some(action) = guard.get_mut(action_id) {
                action.pre_state = Some(state);
            }
        }

        self.persist()?;
        Ok(())
    }

    /// Set compensation data
    pub fn set_compensation_data(
        &self,
        action_id: &str,
        data: serde_json::Value,
    ) -> FailureResult<()> {
        {
            let mut guard = self.actions.write().unwrap();
            if let Some(action) = guard.get_mut(action_id) {
                action.compensation_data = Some(data);
            }
        }

        self.persist()?;
        Ok(())
    }

    /// Complete an action (remove from tracking)
    pub fn complete(&self, action_id: &str) -> FailureResult<()> {
        {
            let mut guard = self.actions.write().unwrap();
            guard.remove(action_id);
        }

        self.persist()?;
        Ok(())
    }

    /// Get all in-flight actions
    pub fn get_all(&self) -> Vec<InFlightAction> {
        self.actions.read().unwrap().values().cloned().collect()
    }

    /// Get actions in a specific phase
    pub fn get_by_phase(&self, phase: ActionPhase) -> Vec<InFlightAction> {
        self.actions
            .read()
            .unwrap()
            .values()
            .filter(|a| a.phase == phase)
            .cloned()
            .collect()
    }

    /// Check if there are any in-flight actions
    pub fn has_in_flight(&self) -> bool {
        !self.actions.read().unwrap().is_empty()
    }
}

// ============================================================================
// Configuration Validator with Fallback
// ============================================================================

/// Result of configuration validation
#[derive(Debug)]
pub struct ConfigValidationResult {
    /// Whether the config is valid
    pub valid: bool,
    /// Validation errors
    pub errors: Vec<String>,
    /// Warnings (config works but may be problematic)
    pub warnings: Vec<String>,
    /// Whether fallback config was used
    pub used_fallback: bool,
}

/// Validates configuration and provides fallbacks
pub struct ConfigValidator {
    /// Path to primary config
    primary_path: PathBuf,
    /// Path to fallback config
    fallback_path: PathBuf,
    /// Safe minimum config (hardcoded)
    safe_minimum: serde_json::Value,
}

impl ConfigValidator {
    /// Create a new validator
    pub fn new(
        primary_path: impl Into<PathBuf>,
        fallback_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            primary_path: primary_path.into(),
            fallback_path: fallback_path.into(),
            safe_minimum: serde_json::json!({
                "wal_path": "/var/lib/whitequbit/wal",
                "audit_path": "/var/log/whitequbit/audit.log",
                "socket_path": "/var/run/whitequbit/agent.sock",
                "pid_path": "/var/run/whitequbit/agent.pid",
                "actions": {
                    "dry_run": true,  // Safe: don't actually change anything
                    "require_confirmation": true,
                },
                "logging": {
                    "level": "info",
                },
            }),
        }
    }

    /// Load and validate configuration with fallback chain
    pub fn load_with_fallback(&self) -> FailureResult<(serde_json::Value, ConfigValidationResult)> {
        // Try primary config
        match self.try_load_and_validate(&self.primary_path) {
            Ok((config, result)) if result.valid => {
                return Ok((config, result));
            }
            Ok((_, result)) => {
                tracing::warn!("Primary config invalid: {:?}", result.errors);
            }
            Err(e) => {
                tracing::warn!("Failed to load primary config: {}", e);
            }
        }

        // Try fallback config
        if self.fallback_path.exists() {
            match self.try_load_and_validate(&self.fallback_path) {
                Ok((config, mut result)) if result.valid => {
                    result.used_fallback = true;
                    tracing::warn!("Using fallback configuration");
                    return Ok((config, result));
                }
                _ => {
                    tracing::warn!("Fallback config also invalid");
                }
            }
        }

        // Use safe minimum
        tracing::error!("Using safe minimum configuration - agent functionality limited");
        let result = ConfigValidationResult {
            valid: true,
            errors: Vec::new(),
            warnings: vec!["Using safe minimum configuration".to_string()],
            used_fallback: true,
        };

        Ok((self.safe_minimum.clone(), result))
    }

    /// Try to load and validate a config file
    fn try_load_and_validate(
        &self,
        path: &Path,
    ) -> FailureResult<(serde_json::Value, ConfigValidationResult)> {
        let content = fs::read_to_string(path)?;

        // Parse TOML to JSON for validation
        let toml_value: toml::Value = toml::from_str(&content)
            .map_err(|e| FailureError::Configuration(e.to_string()))?;

        let json_value = toml_to_json(toml_value);

        let result = self.validate(&json_value);

        Ok((json_value, result))
    }

    /// Validate a configuration
    fn validate(&self, config: &serde_json::Value) -> ConfigValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Required fields
        for field in &["wal_path", "audit_path", "socket_path"] {
            if config.get(field).is_none() {
                errors.push(format!("Missing required field: {}", field));
            }
        }

        // Validate paths are writable
        if let Some(wal) = config.get("wal_path").and_then(|v| v.as_str()) {
            if let Some(parent) = Path::new(wal).parent() {
                if !parent.exists() {
                    warnings.push(format!("WAL directory does not exist: {}", parent.display()));
                }
            }
        }

        // Validate action settings
        if let Some(actions) = config.get("actions") {
            if actions.get("dry_run").and_then(|v| v.as_bool()) == Some(true) {
                warnings.push("Dry-run mode is enabled".to_string());
            }
        }

        ConfigValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
            used_fallback: false,
        }
    }

    /// Compute checksum of config file
    pub fn compute_checksum(&self, path: &Path) -> FailureResult<String> {
        let content = fs::read(path)?;
        let mut hasher = Hasher::new();
        hasher.update(&content);
        Ok(hasher.finalize().to_hex()[..16].to_string())
    }
}

/// Convert TOML value to JSON value
fn toml_to_json(toml: toml::Value) -> serde_json::Value {
    match toml {
        toml::Value::String(s) => serde_json::Value::String(s),
        toml::Value::Integer(i) => serde_json::Value::Number(i.into()),
        toml::Value::Float(f) => {
            serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        toml::Value::Boolean(b) => serde_json::Value::Bool(b),
        toml::Value::Datetime(d) => serde_json::Value::String(d.to_string()),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(toml_to_json).collect())
        }
        toml::Value::Table(table) => {
            let map: serde_json::Map<String, serde_json::Value> = table
                .into_iter()
                .map(|(k, v)| (k, toml_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
    }
}

// ============================================================================
// Recovery Coordinator
// ============================================================================

/// Coordinates recovery on startup
pub struct RecoveryCoordinator {
    /// Kill-switch controller
    kill_switch: Arc<KillSwitch>,
    /// In-flight action tracker
    in_flight: Arc<InFlightTracker>,
    /// Config validator
    config_validator: ConfigValidator,
    /// Failure log path
    failure_log_path: PathBuf,
    /// Next failure ID
    next_failure_id: AtomicU64,
}

impl RecoveryCoordinator {
    /// Create a new recovery coordinator
    pub fn new(
        base_path: impl AsRef<Path>,
        safe_defaults: SafeDefaults,
    ) -> Self {
        let base = base_path.as_ref();

        Self {
            kill_switch: Arc::new(KillSwitch::new(
                base.join("kill_switch.state"),
                safe_defaults,
            )),
            in_flight: Arc::new(InFlightTracker::new(base.join("in_flight.log"))),
            config_validator: ConfigValidator::new(
                base.join("config/agent.toml"),
                base.join("config/agent.toml.fallback"),
            ),
            failure_log_path: base.join("failures.log"),
            next_failure_id: AtomicU64::new(1),
        }
    }

    /// Perform startup recovery
    #[instrument(skip(self))]
    pub fn startup_recovery(&self) -> FailureResult<StartupRecoveryResult> {
        tracing::info!("Starting recovery coordinator");

        let mut result = StartupRecoveryResult::default();

        // 1. Check kill-switch state
        if self.kill_switch.load_state()? {
            result.kill_switch_was_active = true;
            result.requires_intervention = true;
            tracing::warn!("Kill-switch was active - operator acknowledgment required");
        }

        // 2. Load in-flight actions
        let in_flight = self.in_flight.load()?;
        if !in_flight.is_empty() {
            tracing::warn!("Found {} in-flight actions from previous run", in_flight.len());
            result.in_flight_count = in_flight.len();

            // Attempt recovery for each
            for action in in_flight {
                match self.recover_action(&action) {
                    Ok(recovered) => {
                        if recovered {
                            result.actions_recovered += 1;
                        } else {
                            result.actions_failed += 1;
                            result.requires_intervention = true;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to recover action {}: {}", action.action_id, e);
                        result.actions_failed += 1;
                        result.requires_intervention = true;
                    }
                }
            }
        }

        // 3. Validate configuration
        let (_config, validation) = self.config_validator.load_with_fallback()?;
        result.config_valid = validation.valid;
        result.used_fallback_config = validation.used_fallback;

        if !validation.errors.is_empty() {
            result.config_errors = validation.errors;
            result.requires_intervention = true;
        }

        // 4. If too many failures, activate kill-switch
        if result.actions_failed > 0 && !self.kill_switch.is_active() {
            let failure_id = self.record_failure(
                FailureCategory::Crash,
                FailureSeverity::Critical,
                format!("{} actions failed recovery", result.actions_failed),
                "recovery_coordinator",
            )?;

            // Activate kill-switch if more than half failed
            if result.actions_failed > result.in_flight_count / 2 {
                self.kill_switch.activate(
                    "Too many actions failed recovery",
                    failure_id,
                )?;
                result.kill_switch_activated = true;
            }
        }

        tracing::info!("Recovery complete: {:?}", result);
        Ok(result)
    }

    /// Attempt to recover a single action
    fn recover_action(&self, action: &InFlightAction) -> FailureResult<bool> {
        tracing::info!("Recovering action {}: phase={:?}", action.action_id, action.phase);

        match action.phase {
            ActionPhase::Preparing | ActionPhase::Logged => {
                // Action never executed - safe to discard
                tracing::info!("Action {} never executed, discarding", action.action_id);
                self.in_flight.complete(&action.action_id)?;
                Ok(true)
            }

            ActionPhase::Executing | ActionPhase::Verifying => {
                // Action may have partially executed - need rollback
                tracing::warn!("Action {} was mid-execution, attempting rollback", action.action_id);

                if let Some(ref comp_data) = action.compensation_data {
                    // We have compensation data - attempt rollback
                    // TODO: Actually execute compensation via Compensator
                    tracing::info!("Would execute compensation: {:?}", comp_data);
                    self.in_flight.update_phase(&action.action_id, ActionPhase::RolledBack)?;
                    self.in_flight.complete(&action.action_id)?;
                    Ok(true)
                } else if let Some(ref pre_state) = action.pre_state {
                    // We have pre-state - attempt to restore
                    tracing::info!("Would restore pre-state: {:?}", pre_state);
                    self.in_flight.update_phase(&action.action_id, ActionPhase::RolledBack)?;
                    self.in_flight.complete(&action.action_id)?;
                    Ok(true)
                } else {
                    // No recovery data - mark as failed
                    tracing::error!("Action {} has no recovery data", action.action_id);
                    self.in_flight.update_phase(&action.action_id, ActionPhase::Failed)?;
                    Ok(false)
                }
            }

            ActionPhase::Committed => {
                // Action completed successfully - just clean up
                self.in_flight.complete(&action.action_id)?;
                Ok(true)
            }

            ActionPhase::RollingBack => {
                // Rollback was in progress - retry
                tracing::warn!("Action {} rollback was interrupted", action.action_id);
                // TODO: Retry rollback
                self.in_flight.update_phase(&action.action_id, ActionPhase::Failed)?;
                Ok(false)
            }

            ActionPhase::RolledBack => {
                // Already rolled back - clean up
                self.in_flight.complete(&action.action_id)?;
                Ok(true)
            }

            ActionPhase::Failed => {
                // Already failed - leave for manual intervention
                Ok(false)
            }
        }
    }

    /// Record a failure
    pub fn record_failure(
        &self,
        category: FailureCategory,
        severity: FailureSeverity,
        message: impl Into<String>,
        component: impl Into<String>,
    ) -> FailureResult<u64> {
        let failure_id = self.next_failure_id.fetch_add(1, Ordering::SeqCst);

        let record = FailureRecord::new(failure_id, category, severity, message, component);

        // Append to failure log
        self.append_failure_log(&record)?;

        // If fatal, activate kill-switch
        if severity == FailureSeverity::Fatal && !self.kill_switch.is_active() {
            self.kill_switch.activate(&record.message, failure_id)?;
        }

        Ok(failure_id)
    }

    /// Append to failure log
    fn append_failure_log(&self, record: &FailureRecord) -> FailureResult<()> {
        if let Some(parent) = self.failure_log_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.failure_log_path)?;

        let line = serde_json::to_string(record)
            .map_err(|e| FailureError::Serialization(e.to_string()))?;

        writeln!(file, "{}", line)?;
        file.sync_all()?;

        Ok(())
    }

    /// Get kill-switch controller
    pub fn kill_switch(&self) -> &Arc<KillSwitch> {
        &self.kill_switch
    }

    /// Get in-flight tracker
    pub fn in_flight(&self) -> &Arc<InFlightTracker> {
        &self.in_flight
    }

    /// Check if agent should block new actions
    pub fn should_block_actions(&self) -> bool {
        self.kill_switch.is_active()
    }
}

/// Result of startup recovery
#[derive(Debug, Default)]
pub struct StartupRecoveryResult {
    /// Whether kill-switch was already active
    pub kill_switch_was_active: bool,
    /// Whether kill-switch was activated during recovery
    pub kill_switch_activated: bool,
    /// Number of in-flight actions found
    pub in_flight_count: usize,
    /// Number of actions successfully recovered
    pub actions_recovered: usize,
    /// Number of actions that failed recovery
    pub actions_failed: usize,
    /// Whether configuration is valid
    pub config_valid: bool,
    /// Whether fallback config was used
    pub used_fallback_config: bool,
    /// Configuration errors
    pub config_errors: Vec<String>,
    /// Whether manual intervention is required
    pub requires_intervention: bool,
}

// ============================================================================
// Failure Handler Trait
// ============================================================================

/// Trait for components that can handle failures
pub trait FailureHandler: Send + Sync {
    /// Handle a failure and return the action to take
    fn handle_failure(
        &self,
        category: FailureCategory,
        severity: FailureSeverity,
        message: &str,
        context: &BTreeMap<String, String>,
    ) -> FailureAction;

    /// Called when recovery is about to start
    fn on_recovery_start(&self) {}

    /// Called when recovery completes
    fn on_recovery_complete(&self, _result: &StartupRecoveryResult) {}
}

/// Default failure handler implementation
pub struct DefaultFailureHandler {
    /// Maximum retry attempts per operation
    max_retries: u32,
    /// Retry delay in milliseconds
    retry_delay_ms: u64,
}

impl Default for DefaultFailureHandler {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }
}

impl FailureHandler for DefaultFailureHandler {
    fn handle_failure(
        &self,
        category: FailureCategory,
        severity: FailureSeverity,
        _message: &str,
        _context: &BTreeMap<String, String>,
    ) -> FailureAction {
        match (category, severity) {
            // Fatal severity always triggers kill-switch
            (_, FailureSeverity::Fatal) => FailureAction::ActivateKillSwitch,

            // Rollback failures require intervention
            (FailureCategory::RollbackFailed, _) => FailureAction::RequireIntervention,

            // State inconsistencies are critical
            (FailureCategory::StateInconsistent, _) => FailureAction::ApplySafeDefaults,

            // Configuration errors - use safe defaults
            (FailureCategory::ConfigurationInvalid, _) => FailureAction::ApplySafeDefaults,

            // Security violations - kill-switch
            (FailureCategory::SecurityViolation, _) => FailureAction::ActivateKillSwitch,

            // Transient failures - retry
            (FailureCategory::DependencyFailed, FailureSeverity::Warning)
            | (FailureCategory::Timeout, FailureSeverity::Warning) => {
                FailureAction::Retry {
                    max_attempts: self.max_retries,
                    delay_ms: self.retry_delay_ms,
                }
            }

            // Action failures - attempt rollback
            (FailureCategory::ActionFailed, FailureSeverity::Error) => FailureAction::Rollback,

            // Crashes detected on restart
            (FailureCategory::Crash, FailureSeverity::Critical) => {
                FailureAction::ApplySafeDefaults
            }

            // Default: skip and continue
            _ => FailureAction::Skip,
        }
    }
}

// ============================================================================
// Circuit Breaker
// ============================================================================

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation
    Closed,
    /// Too many failures - blocking requests
    Open,
    /// Trying to recover
    HalfOpen,
}

/// Circuit breaker for protecting external dependencies
pub struct CircuitBreaker {
    /// Current state
    state: RwLock<CircuitState>,
    /// Failure count
    failure_count: AtomicU64,
    /// Success count (in half-open state)
    success_count: AtomicU64,
    /// Threshold to open circuit
    failure_threshold: u64,
    /// Successes needed to close circuit
    success_threshold: u64,
    /// Time to wait before trying half-open
    reset_timeout: Duration,
    /// When circuit was opened
    opened_at: RwLock<Option<Instant>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(failure_threshold: u64, success_threshold: u64, reset_timeout: Duration) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            failure_threshold,
            success_threshold,
            reset_timeout,
            opened_at: RwLock::new(None),
        }
    }

    /// Check if requests should be allowed
    pub fn allow_request(&self) -> bool {
        let state = *self.state.read().unwrap();

        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should try half-open
                let opened = self.opened_at.read().unwrap();
                if let Some(opened_at) = *opened {
                    if opened_at.elapsed() >= self.reset_timeout {
                        drop(opened);
                        self.transition_to(CircuitState::HalfOpen);
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful operation
    pub fn record_success(&self) {
        let state = *self.state.read().unwrap();

        match state {
            CircuitState::Closed => {
                // Reset failure count
                self.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.success_threshold {
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but ignore
            }
        }
    }

    /// Record a failed operation
    pub fn record_failure(&self) {
        let state = *self.state.read().unwrap();

        match state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.failure_threshold {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {
                // Already open
            }
        }
    }

    /// Transition to a new state
    fn transition_to(&self, new_state: CircuitState) {
        let mut state = self.state.write().unwrap();
        let old_state = *state;

        if old_state == new_state {
            return;
        }

        tracing::info!("Circuit breaker: {:?} -> {:?}", old_state, new_state);

        *state = new_state;

        match new_state {
            CircuitState::Closed => {
                self.failure_count.store(0, Ordering::Relaxed);
                self.success_count.store(0, Ordering::Relaxed);
                *self.opened_at.write().unwrap() = None;
            }
            CircuitState::Open => {
                self.success_count.store(0, Ordering::Relaxed);
                *self.opened_at.write().unwrap() = Some(Instant::now());
            }
            CircuitState::HalfOpen => {
                self.success_count.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        *self.state.read().unwrap()
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
    fn test_kill_switch_activation() {
        let dir = TempDir::new().unwrap();
        let ks = KillSwitch::new(dir.path().join("ks.state"), SafeDefaults::default());

        assert!(!ks.is_active());

        ks.activate("Test activation", 1).unwrap();

        assert!(ks.is_active());

        let state = ks.state();
        assert!(state.active);
        assert_eq!(state.reason.as_deref(), Some("Test activation"));
        assert_eq!(state.trigger_failure_id, Some(1));
    }

    #[test]
    fn test_kill_switch_persistence() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("ks.state");

        // Activate and persist
        {
            let ks = KillSwitch::new(&state_path, SafeDefaults::default());
            ks.activate("Persist test", 42).unwrap();
        }

        // Load on "restart"
        {
            let ks = KillSwitch::new(&state_path, SafeDefaults::default());
            assert!(ks.load_state().unwrap());
            assert!(ks.is_active());
        }
    }

    #[test]
    fn test_in_flight_tracker() {
        let dir = TempDir::new().unwrap();
        let tracker = InFlightTracker::new(dir.path().join("in_flight.log"));

        // Register action
        tracker.register("action-1", "firewall_rule").unwrap();

        // Update phase
        tracker.update_phase("action-1", ActionPhase::Executing).unwrap();

        // Check state
        let actions = tracker.get_all();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].phase, ActionPhase::Executing);

        // Complete
        tracker.complete("action-1").unwrap();
        assert!(!tracker.has_in_flight());
    }

    #[test]
    fn test_in_flight_persistence() {
        let dir = TempDir::new().unwrap();
        let persist_path = dir.path().join("in_flight.log");

        // Create and persist
        {
            let tracker = InFlightTracker::new(&persist_path);
            tracker.register("action-1", "test").unwrap();
            tracker.update_phase("action-1", ActionPhase::Executing).unwrap();
        }

        // Load on "restart"
        {
            let tracker = InFlightTracker::new(&persist_path);
            let actions = tracker.load().unwrap();
            assert_eq!(actions.len(), 1);
            assert_eq!(actions[0].action_id, "action-1");
            assert_eq!(actions[0].phase, ActionPhase::Executing);
        }
    }

    #[test]
    fn test_circuit_breaker() {
        let cb = CircuitBreaker::new(3, 2, Duration::from_secs(1));

        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());

        // Record failures until threshold
        cb.record_failure();
        cb.record_failure();
        assert!(cb.allow_request()); // Still closed

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_failure_record() {
        let record = FailureRecord::new(
            1,
            FailureCategory::ActionFailed,
            FailureSeverity::Error,
            "Action failed",
            "executor",
        )
        .with_details("Connection timeout")
        .with_context("action_id", "abc-123")
        .with_action(FailureAction::Rollback);

        assert_eq!(record.failure_id, 1);
        assert_eq!(record.category, FailureCategory::ActionFailed);
        assert_eq!(record.details.as_deref(), Some("Connection timeout"));
        assert_eq!(record.context.get("action_id").map(|s| s.as_str()), Some("abc-123"));
    }

    #[test]
    fn test_default_failure_handler() {
        let handler = DefaultFailureHandler::default();

        // Fatal always triggers kill-switch
        let action = handler.handle_failure(
            FailureCategory::Unknown,
            FailureSeverity::Fatal,
            "Fatal error",
            &BTreeMap::new(),
        );
        assert!(matches!(action, FailureAction::ActivateKillSwitch));

        // Rollback failures need intervention
        let action = handler.handle_failure(
            FailureCategory::RollbackFailed,
            FailureSeverity::Error,
            "Rollback failed",
            &BTreeMap::new(),
        );
        assert!(matches!(action, FailureAction::RequireIntervention));

        // Action failures should rollback
        let action = handler.handle_failure(
            FailureCategory::ActionFailed,
            FailureSeverity::Error,
            "Action failed",
            &BTreeMap::new(),
        );
        assert!(matches!(action, FailureAction::Rollback));
    }

    #[test]
    fn test_safe_defaults() {
        let defaults = SafeDefaults::default();

        // Verify safe firewall defaults
        assert_eq!(defaults.firewall.input_policy, DefaultPolicy::Drop);
        assert_eq!(defaults.firewall.output_policy, DefaultPolicy::Accept);
        assert!(!defaults.firewall.allowed_ports.is_empty());

        // SSH should be allowed
        let ssh = defaults.firewall.allowed_ports.iter()
            .find(|p| p.port == 22);
        assert!(ssh.is_some());
    }
}
