//! Security Snapshot Module
//!
//! Captures point-in-time system security state for:
//! - Drift detection
//! - Change auditing
//! - Compliance verification
//! - Incident response
//!
//! # Design Principles
//!
//! 1. **No Secrets**: Never captures passwords, keys, tokens, or sensitive data
//! 2. **Serializable**: JSON/CBOR for storage and transmission
//! 3. **Diffable**: Deterministic ordering for meaningful diffs
//! 4. **Fast**: Parallel collection, minimal syscalls, cached where safe
//! 5. **Versioned**: Content-addressable via deterministic hash
//!
//! # Versioning Strategy
//!
//! Each snapshot has a unique `security_version` computed as:
//! ```text
//! security_version = BLAKE3(
//!     sorted(open_ports) ||
//!     sorted(firewall_rules) ||
//!     sorted(critical_services) ||
//!     auth_posture
//! )
//! ```
//!
//! This enables:
//! - **Change detection**: Different hash = something changed
//! - **Deduplication**: Same hash = identical security state
//! - **Ordering**: Timestamps for temporal ordering
//! - **Ancestry**: Optional parent hash for snapshot chains

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, instrument, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors from snapshot operations
#[derive(Error, Debug)]
pub enum SnapshotError {
    /// Failed to collect port information
    #[error("Port collection failed: {0}")]
    PortCollectionFailed(String),

    /// Failed to collect firewall rules
    #[error("Firewall collection failed: {0}")]
    FirewallCollectionFailed(String),

    /// Failed to collect service status
    #[error("Service collection failed: {0}")]
    ServiceCollectionFailed(String),

    /// Failed to collect auth posture
    #[error("Auth posture collection failed: {0}")]
    AuthCollectionFailed(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Timeout during collection
    #[error("Collection timed out after {0:?}")]
    Timeout(Duration),
}

/// Result type for snapshot operations
pub type SnapshotResult<T> = Result<T, SnapshotError>;

// ============================================================================
// Open Ports
// ============================================================================

/// Protocol for network ports
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
}

impl std::fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortProtocol::Tcp => write!(f, "tcp"),
            PortProtocol::Udp => write!(f, "udp"),
        }
    }
}

/// State of a listening port
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    /// Port is listening
    Listen,
    /// Port is established (for connection tracking)
    Established,
    /// Port is in time-wait
    TimeWait,
    /// Unknown state
    Unknown,
}

/// A single open port
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OpenPort {
    /// Protocol (TCP/UDP)
    pub protocol: PortProtocol,
    /// Port number
    pub port: u16,
    /// Bind address (0.0.0.0, ::, or specific IP)
    pub bind_address: IpAddr,
    /// Port state
    pub state: PortState,
    /// Process name (if available, non-sensitive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Whether this is a well-known service port
    pub is_privileged: bool,
}

impl OpenPort {
    /// Create a new open port entry
    pub fn new(protocol: PortProtocol, port: u16, bind_address: IpAddr) -> Self {
        Self {
            protocol,
            port,
            bind_address,
            state: PortState::Listen,
            process_name: None,
            is_privileged: port < 1024,
        }
    }

    /// Set the process name
    pub fn with_process(mut self, name: impl Into<String>) -> Self {
        self.process_name = Some(name.into());
        self
    }

    /// Set the state
    pub fn with_state(mut self, state: PortState) -> Self {
        self.state = state;
        self
    }

    /// Get a canonical string for hashing
    fn canonical_string(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.protocol,
            self.port,
            self.bind_address,
            self.state as u8
        )
    }
}

/// Summary of open ports
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortSummary {
    /// All open ports (sorted for determinism)
    pub ports: Vec<OpenPort>,
    /// Count of TCP ports
    pub tcp_count: usize,
    /// Count of UDP ports
    pub udp_count: usize,
    /// Count of privileged ports (< 1024)
    pub privileged_count: usize,
    /// Ports listening on all interfaces
    pub wildcard_count: usize,
}

impl PortSummary {
    /// Create from a list of ports
    pub fn from_ports(mut ports: Vec<OpenPort>) -> Self {
        // Sort for deterministic ordering
        ports.sort();

        let tcp_count = ports.iter().filter(|p| p.protocol == PortProtocol::Tcp).count();
        let udp_count = ports.iter().filter(|p| p.protocol == PortProtocol::Udp).count();
        let privileged_count = ports.iter().filter(|p| p.is_privileged).count();
        let wildcard_count = ports
            .iter()
            .filter(|p| p.bind_address.is_unspecified())
            .count();

        Self {
            ports,
            tcp_count,
            udp_count,
            privileged_count,
            wildcard_count,
        }
    }

    /// Get canonical bytes for hashing
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for port in &self.ports {
            bytes.extend(port.canonical_string().as_bytes());
            bytes.push(0); // separator
        }
        bytes
    }
}

// ============================================================================
// Firewall Rules
// ============================================================================

/// Firewall rule action (non-sensitive summary)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Allow traffic (default)
    #[default]
    Allow,
    /// Block/drop traffic
    Block,
    /// Reject with response
    Reject,
    /// Rate limit
    RateLimit,
    /// Log only
    Log,
}

/// Direction of traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    /// Incoming traffic
    Inbound,
    /// Outgoing traffic
    Outbound,
    /// Forwarded traffic
    Forward,
}

/// A summarized firewall rule (no sensitive IPs in comments, etc.)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FirewallRuleSummary {
    /// Rule identifier (hash-based, not the original ID)
    pub id: String,
    /// Chain or table
    pub chain: String,
    /// Action
    pub action: RuleAction,
    /// Direction
    pub direction: TrafficDirection,
    /// Protocol (if specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Destination port (if specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Whether rule applies to specific IPs (but not the IPs themselves)
    pub has_source_filter: bool,
    /// Whether rule applies to specific destinations
    pub has_dest_filter: bool,
    /// Whether this rule was created by this agent
    pub agent_managed: bool,
    /// Priority/order
    pub priority: i32,
}

impl FirewallRuleSummary {
    /// Get canonical string for hashing
    fn canonical_string(&self) -> String {
        format!(
            "{}:{}:{:?}:{:?}:{}:{}:{}:{}",
            self.id,
            self.chain,
            self.action,
            self.direction,
            self.has_source_filter,
            self.has_dest_filter,
            self.agent_managed,
            self.priority
        )
    }
}

/// Summary of firewall configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirewallSummary {
    /// Whether firewall is enabled
    pub enabled: bool,
    /// Default inbound policy
    pub default_inbound: RuleAction,
    /// Default outbound policy
    pub default_outbound: RuleAction,
    /// Number of total rules
    pub total_rules: usize,
    /// Number of agent-managed rules
    pub agent_managed_rules: usize,
    /// Summarized rules (sorted)
    pub rules: Vec<FirewallRuleSummary>,
    /// Firewall backend type
    pub backend: String,
}

impl FirewallSummary {
    /// Get canonical bytes for hashing
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.enabled as u8);
        bytes.push(self.default_inbound as u8);
        bytes.push(self.default_outbound as u8);
        bytes.extend(&(self.total_rules as u32).to_le_bytes());
        bytes.extend(&(self.agent_managed_rules as u32).to_le_bytes());
        bytes.extend(self.backend.as_bytes());
        bytes.push(0);
        for rule in &self.rules {
            bytes.extend(rule.canonical_string().as_bytes());
            bytes.push(0);
        }
        bytes
    }
}

// ============================================================================
// Critical Services
// ============================================================================

/// Status of a service
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    /// Service is running
    Running,
    /// Service is stopped
    Stopped,
    /// Service failed
    Failed,
    /// Service status unknown
    Unknown,
    /// Service is starting
    Starting,
    /// Service is stopping
    Stopping,
}

/// A critical system service
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CriticalService {
    /// Service name
    pub name: String,
    /// Current status
    pub status: ServiceStatus,
    /// Whether service is enabled at boot
    pub enabled: bool,
    /// Whether this is a security-critical service
    pub is_security_service: bool,
    /// Service category
    pub category: ServiceCategory,
}

/// Category of service
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCategory {
    /// Authentication service (sshd, pam, etc.)
    Authentication,
    /// Firewall service
    Firewall,
    /// Audit/logging service
    Audit,
    /// Intrusion detection
    IntrusionDetection,
    /// Anti-malware
    AntiMalware,
    /// Network service
    Network,
    /// System service
    System,
    /// Other
    Other,
}

impl CriticalService {
    /// Create a new critical service entry
    pub fn new(name: impl Into<String>, status: ServiceStatus) -> Self {
        Self {
            name: name.into(),
            status,
            enabled: false,
            is_security_service: false,
            category: ServiceCategory::Other,
        }
    }

    /// Mark as security service
    pub fn security_service(mut self, category: ServiceCategory) -> Self {
        self.is_security_service = true;
        self.category = category;
        self
    }

    /// Set enabled status
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Get canonical string for hashing
    fn canonical_string(&self) -> String {
        format!(
            "{}:{}:{}:{}:{:?}",
            self.name,
            self.status as u8,
            self.enabled,
            self.is_security_service,
            self.category
        )
    }
}

/// Summary of critical services
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServicesSummary {
    /// All monitored services (sorted)
    pub services: Vec<CriticalService>,
    /// Count of running services
    pub running_count: usize,
    /// Count of stopped services
    pub stopped_count: usize,
    /// Count of failed services
    pub failed_count: usize,
    /// Count of security services running
    pub security_services_running: usize,
    /// Any critical security service not running
    pub has_security_issues: bool,
}

impl ServicesSummary {
    /// Create from a list of services
    pub fn from_services(mut services: Vec<CriticalService>) -> Self {
        // Sort for deterministic ordering
        services.sort();

        let running_count = services
            .iter()
            .filter(|s| s.status == ServiceStatus::Running)
            .count();
        let stopped_count = services
            .iter()
            .filter(|s| s.status == ServiceStatus::Stopped)
            .count();
        let failed_count = services
            .iter()
            .filter(|s| s.status == ServiceStatus::Failed)
            .count();

        let security_services_running = services
            .iter()
            .filter(|s| s.is_security_service && s.status == ServiceStatus::Running)
            .count();

        let has_security_issues = services.iter().any(|s| {
            s.is_security_service
                && s.enabled
                && s.status != ServiceStatus::Running
        });

        Self {
            services,
            running_count,
            stopped_count,
            failed_count,
            security_services_running,
            has_security_issues,
        }
    }

    /// Get canonical bytes for hashing
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for svc in &self.services {
            bytes.extend(svc.canonical_string().as_bytes());
            bytes.push(0);
        }
        bytes
    }
}

// ============================================================================
// Authentication Posture
// ============================================================================

/// SSH hardening level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshHardeningLevel {
    /// Root login disabled, password auth disabled, key-only
    Hardened,
    /// Some hardening (e.g., root disabled but password allowed)
    Partial,
    /// Default/unhardened configuration
    Default,
    /// SSH not installed or not applicable
    NotApplicable,
    /// Unable to determine
    Unknown,
}

/// Password policy strength
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordPolicyStrength {
    /// Strong policy (complexity, length, aging)
    Strong,
    /// Moderate policy
    Moderate,
    /// Weak or no policy
    Weak,
    /// Unknown
    Unknown,
}

/// Authentication posture summary (high-level, no secrets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPosture {
    /// SSH hardening level
    pub ssh_hardening: SshHardeningLevel,
    /// Whether root login is disabled
    pub root_login_disabled: bool,
    /// Whether password authentication is disabled (key-only)
    pub password_auth_disabled: bool,
    /// Number of users with login shells
    pub users_with_shell: usize,
    /// Number of users with sudo access
    pub sudo_users: usize,
    /// Whether SELinux/AppArmor is enforcing
    pub mac_enforcing: bool,
    /// MAC system type
    pub mac_system: Option<String>,
    /// Password policy strength
    pub password_policy: PasswordPolicyStrength,
    /// Whether 2FA/MFA is configured
    pub mfa_configured: bool,
    /// Number of failed login attempts (last hour)
    pub recent_failed_logins: usize,
    /// Whether audit logging is enabled
    pub audit_enabled: bool,
}

impl Default for AuthPosture {
    fn default() -> Self {
        Self {
            ssh_hardening: SshHardeningLevel::Unknown,
            root_login_disabled: false,
            password_auth_disabled: false,
            users_with_shell: 0,
            sudo_users: 0,
            mac_enforcing: false,
            mac_system: None,
            password_policy: PasswordPolicyStrength::Unknown,
            mfa_configured: false,
            recent_failed_logins: 0,
            audit_enabled: false,
        }
    }
}

impl AuthPosture {
    /// Get canonical bytes for hashing
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.ssh_hardening as u8);
        bytes.push(self.root_login_disabled as u8);
        bytes.push(self.password_auth_disabled as u8);
        bytes.extend(&(self.users_with_shell as u32).to_le_bytes());
        bytes.extend(&(self.sudo_users as u32).to_le_bytes());
        bytes.push(self.mac_enforcing as u8);
        bytes.push(self.password_policy as u8);
        bytes.push(self.mfa_configured as u8);
        bytes.push(self.audit_enabled as u8);
        // Note: recent_failed_logins excluded from hash as it's volatile
        bytes
    }

    /// Compute an overall security score (0-100)
    pub fn security_score(&self) -> u8 {
        let mut score = 50u8; // Base score

        // SSH hardening
        match self.ssh_hardening {
            SshHardeningLevel::Hardened => score = score.saturating_add(15),
            SshHardeningLevel::Partial => score = score.saturating_add(5),
            SshHardeningLevel::Default => {}
            _ => {}
        }

        // Root login
        if self.root_login_disabled {
            score = score.saturating_add(10);
        }

        // Password auth
        if self.password_auth_disabled {
            score = score.saturating_add(10);
        }

        // MAC system
        if self.mac_enforcing {
            score = score.saturating_add(10);
        }

        // Password policy
        match self.password_policy {
            PasswordPolicyStrength::Strong => score = score.saturating_add(5),
            PasswordPolicyStrength::Moderate => score = score.saturating_add(2),
            _ => {}
        }

        // MFA
        if self.mfa_configured {
            score = score.saturating_add(10);
        }

        // Audit
        if self.audit_enabled {
            score = score.saturating_add(5);
        }

        // Cap at 100
        score.min(100)
    }
}

// ============================================================================
// Security Snapshot
// ============================================================================

/// Snapshot metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Unique snapshot ID (UUID)
    pub id: String,
    /// Timestamp when snapshot was taken
    pub timestamp: DateTime<Utc>,
    /// Hostname
    pub hostname: String,
    /// Agent version
    pub agent_version: String,
    /// Collection duration in milliseconds
    pub collection_duration_ms: u64,
    /// Parent snapshot hash (for chain tracking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<String>,
    /// Snapshot sequence number
    pub sequence: u64,
}

/// Complete security snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySnapshot {
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,

    /// Open ports summary
    pub ports: PortSummary,

    /// Firewall configuration summary
    pub firewall: FirewallSummary,

    /// Critical services summary
    pub services: ServicesSummary,

    /// Authentication posture
    pub auth_posture: AuthPosture,

    /// Deterministic security version hash (BLAKE3)
    pub security_version: String,

    /// Computed security score (0-100)
    pub security_score: u8,
}

impl SecuritySnapshot {
    /// Create a new snapshot builder
    pub fn builder() -> SnapshotBuilder {
        SnapshotBuilder::new()
    }

    /// Compute the security version hash
    fn compute_security_version(
        ports: &PortSummary,
        firewall: &FirewallSummary,
        services: &ServicesSummary,
        auth: &AuthPosture,
    ) -> String {
        use blake3::Hasher;

        let mut hasher = Hasher::new();

        // Hash each component in order
        hasher.update(&ports.canonical_bytes());
        hasher.update(&[0xFF]); // separator
        hasher.update(&firewall.canonical_bytes());
        hasher.update(&[0xFF]);
        hasher.update(&services.canonical_bytes());
        hasher.update(&[0xFF]);
        hasher.update(&auth.canonical_bytes());

        // Return hex-encoded hash (first 16 bytes = 32 hex chars)
        let hash = hasher.finalize();
        hash.to_hex().as_str()[..32].to_string()
    }

    /// Check if this snapshot differs from another
    pub fn differs_from(&self, other: &SecuritySnapshot) -> bool {
        self.security_version != other.security_version
    }

    /// Compute a diff between two snapshots
    pub fn diff(&self, other: &SecuritySnapshot) -> SnapshotDiff {
        SnapshotDiff::compute(self, other)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> SnapshotResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| SnapshotError::SerializationError(e.to_string()))
    }

    /// Serialize to compact JSON
    pub fn to_json_compact(&self) -> SnapshotResult<String> {
        serde_json::to_string(self)
            .map_err(|e| SnapshotError::SerializationError(e.to_string()))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> SnapshotResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| SnapshotError::SerializationError(e.to_string()))
    }
}

// ============================================================================
// Snapshot Builder
// ============================================================================

/// Builder for constructing snapshots
pub struct SnapshotBuilder {
    ports: Option<PortSummary>,
    firewall: Option<FirewallSummary>,
    services: Option<ServicesSummary>,
    auth_posture: Option<AuthPosture>,
    parent_hash: Option<String>,
    sequence: u64,
}

impl SnapshotBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            ports: None,
            firewall: None,
            services: None,
            auth_posture: None,
            parent_hash: None,
            sequence: 0,
        }
    }

    /// Set port summary
    pub fn ports(mut self, ports: PortSummary) -> Self {
        self.ports = Some(ports);
        self
    }

    /// Set firewall summary
    pub fn firewall(mut self, firewall: FirewallSummary) -> Self {
        self.firewall = Some(firewall);
        self
    }

    /// Set services summary
    pub fn services(mut self, services: ServicesSummary) -> Self {
        self.services = Some(services);
        self
    }

    /// Set auth posture
    pub fn auth_posture(mut self, auth: AuthPosture) -> Self {
        self.auth_posture = Some(auth);
        self
    }

    /// Set parent hash for chain tracking
    pub fn parent(mut self, hash: impl Into<String>) -> Self {
        self.parent_hash = Some(hash.into());
        self
    }

    /// Set sequence number
    pub fn sequence(mut self, seq: u64) -> Self {
        self.sequence = seq;
        self
    }

    /// Build the snapshot
    pub fn build(self, collection_duration: Duration) -> SecuritySnapshot {
        let ports = self.ports.unwrap_or_default();
        let firewall = self.firewall.unwrap_or_default();
        let services = self.services.unwrap_or_default();
        let auth_posture = self.auth_posture.unwrap_or_default();

        let security_version = SecuritySnapshot::compute_security_version(
            &ports,
            &firewall,
            &services,
            &auth_posture,
        );

        let security_score = auth_posture.security_score();

        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        SecuritySnapshot {
            metadata: SnapshotMetadata {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                hostname,
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                collection_duration_ms: collection_duration.as_millis() as u64,
                parent_hash: self.parent_hash,
                sequence: self.sequence,
            },
            ports,
            firewall,
            services,
            auth_posture,
            security_version,
            security_score,
        }
    }
}

impl Default for SnapshotBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Snapshot Diff
// ============================================================================

/// Type of change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    /// Item was added
    Added,
    /// Item was removed
    Removed,
    /// Item was modified
    Modified,
}

/// A single change between snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChange {
    /// Category of change
    pub category: String,
    /// Type of change
    pub change_type: ChangeType,
    /// Description
    pub description: String,
    /// Old value (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    /// New value (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

/// Diff between two snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiff {
    /// Old snapshot version
    pub old_version: String,
    /// New snapshot version
    pub new_version: String,
    /// Old timestamp
    pub old_timestamp: DateTime<Utc>,
    /// New timestamp
    pub new_timestamp: DateTime<Utc>,
    /// Time between snapshots
    pub duration_seconds: i64,
    /// Whether security version changed
    pub version_changed: bool,
    /// Security score delta
    pub score_delta: i16,
    /// List of changes
    pub changes: Vec<SnapshotChange>,
    /// Number of ports added
    pub ports_added: usize,
    /// Number of ports removed
    pub ports_removed: usize,
    /// Number of rules added
    pub rules_added: usize,
    /// Number of rules removed
    pub rules_removed: usize,
    /// Number of service status changes
    pub service_changes: usize,
}

impl SnapshotDiff {
    /// Compute diff between two snapshots
    pub fn compute(old: &SecuritySnapshot, new: &SecuritySnapshot) -> Self {
        let mut changes = Vec::new();

        // Compare ports
        let old_ports: BTreeSet<_> = old.ports.ports.iter().collect();
        let new_ports: BTreeSet<_> = new.ports.ports.iter().collect();

        let ports_added = new_ports.difference(&old_ports).count();
        let ports_removed = old_ports.difference(&new_ports).count();

        for port in new_ports.difference(&old_ports) {
            changes.push(SnapshotChange {
                category: "ports".to_string(),
                change_type: ChangeType::Added,
                description: format!(
                    "Port {}:{} opened",
                    port.protocol, port.port
                ),
                old_value: None,
                new_value: Some(format!("{}:{}", port.protocol, port.port)),
            });
        }

        for port in old_ports.difference(&new_ports) {
            changes.push(SnapshotChange {
                category: "ports".to_string(),
                change_type: ChangeType::Removed,
                description: format!(
                    "Port {}:{} closed",
                    port.protocol, port.port
                ),
                old_value: Some(format!("{}:{}", port.protocol, port.port)),
                new_value: None,
            });
        }

        // Compare firewall rules
        let old_rules: BTreeSet<_> = old.firewall.rules.iter().map(|r| &r.id).collect();
        let new_rules: BTreeSet<_> = new.firewall.rules.iter().map(|r| &r.id).collect();

        let rules_added = new_rules.difference(&old_rules).count();
        let rules_removed = old_rules.difference(&new_rules).count();

        // Compare services
        let old_services: BTreeMap<_, _> = old.services.services.iter()
            .map(|s| (&s.name, &s.status))
            .collect();
        let new_services: BTreeMap<_, _> = new.services.services.iter()
            .map(|s| (&s.name, &s.status))
            .collect();

        let mut service_changes = 0;
        for (name, new_status) in &new_services {
            if let Some(old_status) = old_services.get(name) {
                if old_status != new_status {
                    service_changes += 1;
                    changes.push(SnapshotChange {
                        category: "services".to_string(),
                        change_type: ChangeType::Modified,
                        description: format!("Service {} status changed", name),
                        old_value: Some(format!("{:?}", old_status)),
                        new_value: Some(format!("{:?}", new_status)),
                    });
                }
            }
        }

        // Compare auth posture
        if old.auth_posture.ssh_hardening != new.auth_posture.ssh_hardening {
            changes.push(SnapshotChange {
                category: "auth".to_string(),
                change_type: ChangeType::Modified,
                description: "SSH hardening level changed".to_string(),
                old_value: Some(format!("{:?}", old.auth_posture.ssh_hardening)),
                new_value: Some(format!("{:?}", new.auth_posture.ssh_hardening)),
            });
        }

        if old.auth_posture.root_login_disabled != new.auth_posture.root_login_disabled {
            changes.push(SnapshotChange {
                category: "auth".to_string(),
                change_type: ChangeType::Modified,
                description: "Root login policy changed".to_string(),
                old_value: Some(format!("{}", old.auth_posture.root_login_disabled)),
                new_value: Some(format!("{}", new.auth_posture.root_login_disabled)),
            });
        }

        let duration_seconds = (new.metadata.timestamp - old.metadata.timestamp).num_seconds();
        let score_delta = new.security_score as i16 - old.security_score as i16;

        Self {
            old_version: old.security_version.clone(),
            new_version: new.security_version.clone(),
            old_timestamp: old.metadata.timestamp,
            new_timestamp: new.metadata.timestamp,
            duration_seconds,
            version_changed: old.security_version != new.security_version,
            score_delta,
            changes,
            ports_added,
            ports_removed,
            rules_added,
            rules_removed,
            service_changes,
        }
    }

    /// Check if there are any changes
    pub fn has_changes(&self) -> bool {
        self.version_changed
    }

    /// Check if security degraded
    pub fn security_degraded(&self) -> bool {
        self.score_delta < 0
    }
}

// ============================================================================
// Collector Traits
// ============================================================================

/// Trait for collecting port information
#[async_trait::async_trait]
pub trait PortCollector: Send + Sync {
    /// Collect open ports
    async fn collect(&self) -> SnapshotResult<Vec<OpenPort>>;
}

/// Trait for collecting firewall information
#[async_trait::async_trait]
pub trait FirewallCollector: Send + Sync {
    /// Collect firewall summary
    async fn collect(&self) -> SnapshotResult<FirewallSummary>;
}

/// Trait for collecting service information
#[async_trait::async_trait]
pub trait ServiceCollector: Send + Sync {
    /// Collect critical services
    async fn collect(&self) -> SnapshotResult<Vec<CriticalService>>;
}

/// Trait for collecting auth posture
#[async_trait::async_trait]
pub trait AuthCollector: Send + Sync {
    /// Collect authentication posture
    async fn collect(&self) -> SnapshotResult<AuthPosture>;
}

// ============================================================================
// Snapshot Collector
// ============================================================================

/// Configuration for snapshot collection
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    /// Timeout for collection
    pub timeout: Duration,
    /// Whether to collect ports
    pub collect_ports: bool,
    /// Whether to collect firewall
    pub collect_firewall: bool,
    /// Whether to collect services
    pub collect_services: bool,
    /// Whether to collect auth posture
    pub collect_auth: bool,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            collect_ports: true,
            collect_firewall: true,
            collect_services: true,
            collect_auth: true,
        }
    }
}

/// Snapshot collector orchestrator
pub struct SnapshotCollector {
    /// Configuration
    config: SnapshotConfig,
    /// Port collector
    port_collector: Option<Box<dyn PortCollector>>,
    /// Firewall collector
    firewall_collector: Option<Box<dyn FirewallCollector>>,
    /// Service collector
    service_collector: Option<Box<dyn ServiceCollector>>,
    /// Auth collector
    auth_collector: Option<Box<dyn AuthCollector>>,
    /// Last snapshot for chain tracking
    last_snapshot_hash: Option<String>,
    /// Snapshot sequence counter
    sequence: std::sync::atomic::AtomicU64,
}

impl SnapshotCollector {
    /// Create a new collector
    pub fn new(config: SnapshotConfig) -> Self {
        Self {
            config,
            port_collector: None,
            firewall_collector: None,
            service_collector: None,
            auth_collector: None,
            last_snapshot_hash: None,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Set port collector
    pub fn with_port_collector(mut self, collector: Box<dyn PortCollector>) -> Self {
        self.port_collector = Some(collector);
        self
    }

    /// Set firewall collector
    pub fn with_firewall_collector(mut self, collector: Box<dyn FirewallCollector>) -> Self {
        self.firewall_collector = Some(collector);
        self
    }

    /// Set service collector
    pub fn with_service_collector(mut self, collector: Box<dyn ServiceCollector>) -> Self {
        self.service_collector = Some(collector);
        self
    }

    /// Set auth collector
    pub fn with_auth_collector(mut self, collector: Box<dyn AuthCollector>) -> Self {
        self.auth_collector = Some(collector);
        self
    }

    /// Collect a snapshot
    #[instrument(skip(self))]
    pub async fn collect(&mut self) -> SnapshotResult<SecuritySnapshot> {
        let start = Instant::now();
        info!("Starting security snapshot collection");

        let mut builder = SecuritySnapshot::builder();

        // Set chain tracking
        if let Some(ref parent) = self.last_snapshot_hash {
            builder = builder.parent(parent.clone());
        }

        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        builder = builder.sequence(seq);

        // Collect ports
        if self.config.collect_ports {
            if let Some(ref collector) = self.port_collector {
                match collector.collect().await {
                    Ok(ports) => {
                        builder = builder.ports(PortSummary::from_ports(ports));
                    }
                    Err(e) => {
                        warn!(?e, "Failed to collect ports");
                    }
                }
            }
        }

        // Collect firewall
        if self.config.collect_firewall {
            if let Some(ref collector) = self.firewall_collector {
                match collector.collect().await {
                    Ok(fw) => {
                        builder = builder.firewall(fw);
                    }
                    Err(e) => {
                        warn!(?e, "Failed to collect firewall");
                    }
                }
            }
        }

        // Collect services
        if self.config.collect_services {
            if let Some(ref collector) = self.service_collector {
                match collector.collect().await {
                    Ok(services) => {
                        builder = builder.services(ServicesSummary::from_services(services));
                    }
                    Err(e) => {
                        warn!(?e, "Failed to collect services");
                    }
                }
            }
        }

        // Collect auth posture
        if self.config.collect_auth {
            if let Some(ref collector) = self.auth_collector {
                match collector.collect().await {
                    Ok(auth) => {
                        builder = builder.auth_posture(auth);
                    }
                    Err(e) => {
                        warn!(?e, "Failed to collect auth posture");
                    }
                }
            }
        }

        let duration = start.elapsed();
        let snapshot = builder.build(duration);

        // Update chain tracking
        self.last_snapshot_hash = Some(snapshot.security_version.clone());

        info!(
            version = %snapshot.security_version,
            score = snapshot.security_score,
            duration_ms = duration.as_millis() as u64,
            "Snapshot collection complete"
        );

        Ok(snapshot)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_port_summary_determinism() {
        let ports1 = vec![
            OpenPort::new(PortProtocol::Tcp, 443, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            OpenPort::new(PortProtocol::Tcp, 80, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            OpenPort::new(PortProtocol::Udp, 53, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];

        // Same ports, different order
        let ports2 = vec![
            OpenPort::new(PortProtocol::Udp, 53, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            OpenPort::new(PortProtocol::Tcp, 80, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            OpenPort::new(PortProtocol::Tcp, 443, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ];

        let summary1 = PortSummary::from_ports(ports1);
        let summary2 = PortSummary::from_ports(ports2);

        // Should produce identical canonical bytes
        assert_eq!(summary1.canonical_bytes(), summary2.canonical_bytes());
    }

    #[test]
    fn test_security_version_determinism() {
        let ports = PortSummary::from_ports(vec![
            OpenPort::new(PortProtocol::Tcp, 22, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ]);

        let firewall = FirewallSummary::default();
        let services = ServicesSummary::default();
        let auth = AuthPosture::default();

        let version1 = SecuritySnapshot::compute_security_version(
            &ports, &firewall, &services, &auth
        );

        let version2 = SecuritySnapshot::compute_security_version(
            &ports, &firewall, &services, &auth
        );

        assert_eq!(version1, version2);
    }

    #[test]
    fn test_security_version_changes_on_diff() {
        let ports1 = PortSummary::from_ports(vec![
            OpenPort::new(PortProtocol::Tcp, 22, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ]);

        let ports2 = PortSummary::from_ports(vec![
            OpenPort::new(PortProtocol::Tcp, 22, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            OpenPort::new(PortProtocol::Tcp, 80, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ]);

        let firewall = FirewallSummary::default();
        let services = ServicesSummary::default();
        let auth = AuthPosture::default();

        let version1 = SecuritySnapshot::compute_security_version(
            &ports1, &firewall, &services, &auth
        );

        let version2 = SecuritySnapshot::compute_security_version(
            &ports2, &firewall, &services, &auth
        );

        assert_ne!(version1, version2);
    }

    #[test]
    fn test_auth_posture_score() {
        let mut auth = AuthPosture::default();
        let base_score = auth.security_score();
        assert_eq!(base_score, 50); // Base score

        auth.ssh_hardening = SshHardeningLevel::Hardened;
        auth.root_login_disabled = true;
        auth.password_auth_disabled = true;
        auth.mac_enforcing = true;
        auth.password_policy = PasswordPolicyStrength::Strong;
        auth.mfa_configured = true;
        auth.audit_enabled = true;

        let max_score = auth.security_score();
        assert_eq!(max_score, 100); // Max score
    }

    #[test]
    fn test_snapshot_builder() {
        let snapshot = SecuritySnapshot::builder()
            .ports(PortSummary::default())
            .firewall(FirewallSummary::default())
            .services(ServicesSummary::default())
            .auth_posture(AuthPosture::default())
            .sequence(1)
            .build(Duration::from_millis(100));

        assert!(!snapshot.security_version.is_empty());
        assert_eq!(snapshot.metadata.sequence, 1);
    }

    #[test]
    fn test_snapshot_diff_no_changes() {
        let snapshot1 = SecuritySnapshot::builder()
            .build(Duration::from_millis(100));

        let snapshot2 = SecuritySnapshot::builder()
            .build(Duration::from_millis(100));

        let diff = snapshot1.diff(&snapshot2);

        assert!(!diff.has_changes()); // Same content, same hash
        assert_eq!(diff.score_delta, 0);
    }

    #[test]
    fn test_snapshot_diff_with_changes() {
        let ports1 = PortSummary::from_ports(vec![
            OpenPort::new(PortProtocol::Tcp, 22, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ]);

        let ports2 = PortSummary::from_ports(vec![
            OpenPort::new(PortProtocol::Tcp, 22, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            OpenPort::new(PortProtocol::Tcp, 80, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ]);

        let snapshot1 = SecuritySnapshot::builder()
            .ports(ports1)
            .build(Duration::from_millis(100));

        let snapshot2 = SecuritySnapshot::builder()
            .ports(ports2)
            .build(Duration::from_millis(100));

        let diff = snapshot1.diff(&snapshot2);

        assert!(diff.has_changes());
        assert_eq!(diff.ports_added, 1);
        assert_eq!(diff.ports_removed, 0);
    }

    #[test]
    fn test_services_summary_security_issues() {
        let services = vec![
            CriticalService::new("sshd", ServiceStatus::Running)
                .security_service(ServiceCategory::Authentication)
                .with_enabled(true),
            CriticalService::new("iptables", ServiceStatus::Stopped)
                .security_service(ServiceCategory::Firewall)
                .with_enabled(true), // Enabled but stopped = issue
        ];

        let summary = ServicesSummary::from_services(services);
        assert!(summary.has_security_issues);
        assert_eq!(summary.security_services_running, 1);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let snapshot = SecuritySnapshot::builder()
            .ports(PortSummary::from_ports(vec![
                OpenPort::new(PortProtocol::Tcp, 22, IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                    .with_process("sshd".to_string()),
            ]))
            .build(Duration::from_millis(100));

        let json = snapshot.to_json().unwrap();
        let restored = SecuritySnapshot::from_json(&json).unwrap();

        assert_eq!(snapshot.security_version, restored.security_version);
        assert_eq!(snapshot.ports.ports.len(), restored.ports.ports.len());
    }
}
