//! Firewall Abstraction Layer
//!
//! This module provides a platform-agnostic interface for firewall operations.
//! The design prioritizes:
//! - **Idempotency**: Operations can be safely retried
//! - **Strict Validation**: All inputs validated before execution
//! - **Explicit Errors**: Typed errors for all failure modes
//! - **Rollback Support**: Undo last N operations
//! - **Extensibility**: Easy to add new backends (iptables, nftables, Windows Firewall, pf)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    FirewallManager                               │
//! │  - Orchestrates operations                                       │
//! │  - Maintains action history for rollback                         │
//! │  - Handles TTL expiration                                        │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    FirewallBackend (trait)                       │
//! │  - Platform-specific implementation                              │
//! │  - iptables, nftables, Windows Firewall, pf                      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! let manager = FirewallManager::new(backend);
//!
//! // Block an IP
//! manager.block_ip("192.168.1.100".parse()?).await?;
//!
//! // Temporary block with 1 hour TTL
//! manager.block_ip_with_ttl("10.0.0.5".parse()?, Duration::from_secs(3600)).await?;
//!
//! // Rate limit
//! manager.rate_limit_ip("8.8.8.8".parse()?, RateLimitPolicy::default()).await?;
//!
//! // Rollback last 3 actions
//! manager.rollback(3).await?;
//! ```

// Platform-specific backends
#[cfg(target_os = "linux")]
pub mod iptables;

// TTL engine for temporary rules
pub mod ttl;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from firewall operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FirewallError {
    /// Invalid IP address format
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    /// Invalid CIDR notation
    #[error("Invalid CIDR: {value} - {reason}")]
    InvalidCidr {
        /// The invalid CIDR value
        value: String,
        /// The reason it's invalid
        reason: String,
    },

    /// Invalid port number
    #[error("Invalid port: {0}")]
    InvalidPort(u16),

    /// Invalid rate limit configuration
    #[error("Invalid rate limit: {0}")]
    InvalidRateLimit(String),

    /// Invalid TTL duration
    #[error("Invalid TTL: {0}")]
    InvalidTtl(String),

    /// Rule already exists (for idempotency reporting)
    #[error("Rule already exists: {0}")]
    RuleAlreadyExists(String),

    /// Rule not found (for removal operations)
    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    /// Backend execution failed
    #[error("Backend error: {0}")]
    BackendError(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Backend not available
    #[error("Backend not available: {0}")]
    BackendUnavailable(String),

    /// Operation timed out
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),

    /// Rollback failed
    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    /// No actions to rollback
    #[error("No actions to rollback")]
    NoActionsToRollback,

    /// Rate limit exceeded for management operations
    #[error("Too many firewall operations, rate limited")]
    RateLimited,

    /// Rule conflicts with existing rule
    #[error("Rule conflict: {0}")]
    RuleConflict(String),

    /// Maximum rules exceeded
    #[error("Maximum rules exceeded: limit is {0}")]
    MaxRulesExceeded(usize),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for firewall operations
pub type FirewallResult<T> = Result<T, FirewallError>;

// ============================================================================
// IP Address Types with Strict Validation
// ============================================================================

/// A validated IPv4 or IPv6 address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatedIp(IpAddr);

impl ValidatedIp {
    /// Create a new validated IP, rejecting special addresses
    pub fn new(ip: IpAddr) -> FirewallResult<Self> {
        Self::validate(&ip)?;
        Ok(Self(ip))
    }

    /// Validate an IP address for firewall use
    fn validate(ip: &IpAddr) -> FirewallResult<()> {
        match ip {
            IpAddr::V4(v4) => Self::validate_v4(v4),
            IpAddr::V6(v6) => Self::validate_v6(v6),
        }
    }

    fn validate_v4(ip: &Ipv4Addr) -> FirewallResult<()> {
        // Reject unspecified (0.0.0.0)
        if ip.is_unspecified() {
            return Err(FirewallError::InvalidIpAddress(
                "Cannot use unspecified address 0.0.0.0".to_string(),
            ));
        }

        // Reject broadcast (255.255.255.255)
        if ip.is_broadcast() {
            return Err(FirewallError::InvalidIpAddress(
                "Cannot use broadcast address".to_string(),
            ));
        }

        // Allow but warn for loopback (127.x.x.x) - caller's responsibility
        // Allow private ranges - they're valid targets

        Ok(())
    }

    fn validate_v6(ip: &Ipv6Addr) -> FirewallResult<()> {
        // Reject unspecified (::)
        if ip.is_unspecified() {
            return Err(FirewallError::InvalidIpAddress(
                "Cannot use unspecified address ::".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the inner IP address
    pub fn ip(&self) -> IpAddr {
        self.0
    }

    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        self.0.is_ipv4()
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        self.0.is_ipv6()
    }

    /// Check if this is a loopback address
    pub fn is_loopback(&self) -> bool {
        self.0.is_loopback()
    }

    /// Check if this is a private address
    pub fn is_private(&self) -> bool {
        match self.0 {
            IpAddr::V4(v4) => v4.is_private(),
            IpAddr::V6(_) => false, // IPv6 private detection is more complex
        }
    }
}

impl fmt::Display for ValidatedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ValidatedIp {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: IpAddr = s
            .parse()
            .map_err(|_| FirewallError::InvalidIpAddress(s.to_string()))?;
        Self::new(ip)
    }
}

impl From<ValidatedIp> for IpAddr {
    fn from(validated: ValidatedIp) -> Self {
        validated.0
    }
}

/// A validated CIDR block
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatedCidr {
    /// Network address
    network: IpAddr,
    /// Prefix length (0-32 for IPv4, 0-128 for IPv6)
    prefix_len: u8,
}

impl ValidatedCidr {
    /// Create a new validated CIDR block
    pub fn new(network: IpAddr, prefix_len: u8) -> FirewallResult<Self> {
        let max_prefix = if network.is_ipv4() { 32 } else { 128 };

        if prefix_len > max_prefix {
            return Err(FirewallError::InvalidCidr {
                value: format!("{}/{}", network, prefix_len),
                reason: format!("Prefix length {} exceeds maximum {}", prefix_len, max_prefix),
            });
        }

        // Validate the network address is actually a network (not a host in the middle)
        // This is a simplified check - production would normalize the address

        Ok(Self { network, prefix_len })
    }

    /// Get the network address
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// Get the prefix length
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Check if an IP is contained in this CIDR
    pub fn contains(&self, ip: &ValidatedIp) -> bool {
        // Simplified containment check
        match (self.network, ip.ip()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let net_bits: u128 = net.into();
                let ip_bits: u128 = ip.into();
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (net_bits & mask) == (ip_bits & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }
}

impl fmt::Display for ValidatedCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for ValidatedCidr {
    type Err = FirewallError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(FirewallError::InvalidCidr {
                value: s.to_string(),
                reason: "Expected format: IP/prefix".to_string(),
            });
        }

        let network: IpAddr = parts[0]
            .parse()
            .map_err(|_| FirewallError::InvalidCidr {
                value: s.to_string(),
                reason: "Invalid IP address".to_string(),
            })?;

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| FirewallError::InvalidCidr {
                value: s.to_string(),
                reason: "Invalid prefix length".to_string(),
            })?;

        Self::new(network, prefix_len)
    }
}

// ============================================================================
// Firewall Rule Types
// ============================================================================

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// All protocols
    #[default]
    All,
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP (v4) / ICMPv6
    Icmp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::All => write!(f, "all"),
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
        }
    }
}

/// Traffic direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Incoming traffic
    #[default]
    Inbound,
    /// Outgoing traffic
    Outbound,
    /// Both directions
    Both,
}

/// Rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Block/drop the traffic
    Block,
    /// Allow the traffic
    Allow,
    /// Rate limit the traffic
    RateLimit,
    /// Log and allow
    LogAllow,
    /// Log and block
    LogBlock,
}

/// Rate limiting policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    /// Maximum packets per second
    pub packets_per_second: u32,
    /// Maximum bytes per second (optional)
    pub bytes_per_second: Option<u64>,
    /// Burst allowance (packets)
    pub burst: u32,
    /// What to do when limit exceeded
    pub exceed_action: ExceedAction,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            packets_per_second: 100,
            bytes_per_second: None,
            burst: 50,
            exceed_action: ExceedAction::Drop,
        }
    }
}

impl RateLimitPolicy {
    /// Create a strict rate limit (low threshold)
    pub fn strict() -> Self {
        Self {
            packets_per_second: 10,
            bytes_per_second: Some(10_000),
            burst: 5,
            exceed_action: ExceedAction::Drop,
        }
    }

    /// Create a permissive rate limit (high threshold)
    pub fn permissive() -> Self {
        Self {
            packets_per_second: 1000,
            bytes_per_second: None,
            burst: 500,
            exceed_action: ExceedAction::Drop,
        }
    }

    /// Validate the policy
    pub fn validate(&self) -> FirewallResult<()> {
        if self.packets_per_second == 0 {
            return Err(FirewallError::InvalidRateLimit(
                "packets_per_second must be > 0".to_string(),
            ));
        }
        if self.burst == 0 {
            return Err(FirewallError::InvalidRateLimit(
                "burst must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Action when rate limit is exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExceedAction {
    /// Drop excess packets
    #[default]
    Drop,
    /// Reject with ICMP error
    Reject,
    /// Log and drop
    LogDrop,
    /// Log and allow (for monitoring only)
    LogAllow,
}

/// Time-to-live specification for temporary rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTtl {
    /// Duration until rule expires
    duration: Duration,
}

impl RuleTtl {
    /// Create a new TTL
    pub fn new(duration: Duration) -> FirewallResult<Self> {
        // Minimum 1 second
        if duration.as_secs() == 0 && duration.subsec_nanos() == 0 {
            return Err(FirewallError::InvalidTtl("TTL must be > 0".to_string()));
        }

        // Maximum 30 days
        const MAX_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
        if duration > MAX_TTL {
            return Err(FirewallError::InvalidTtl(format!(
                "TTL exceeds maximum of {:?}",
                MAX_TTL
            )));
        }

        Ok(Self { duration })
    }

    /// Create TTL from seconds
    pub fn from_secs(secs: u64) -> FirewallResult<Self> {
        Self::new(Duration::from_secs(secs))
    }

    /// Create TTL from minutes
    pub fn from_mins(mins: u64) -> FirewallResult<Self> {
        Self::new(Duration::from_secs(mins * 60))
    }

    /// Create TTL from hours
    pub fn from_hours(hours: u64) -> FirewallResult<Self> {
        Self::new(Duration::from_secs(hours * 60 * 60))
    }

    /// Get the duration
    pub fn duration(&self) -> Duration {
        self.duration
    }
}

// ============================================================================
// Rule Identifier
// ============================================================================

/// Unique identifier for a firewall rule
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(String);

impl RuleId {
    /// Create a new rule ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a new unique rule ID
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for RuleId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// ============================================================================
// Firewall Rule Definition
// ============================================================================

/// A complete firewall rule specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRuleSpec {
    /// Unique rule identifier
    pub id: RuleId,
    /// Source IP or CIDR (None = any)
    pub source: Option<IpTarget>,
    /// Destination IP or CIDR (None = any)
    pub destination: Option<IpTarget>,
    /// Protocol
    pub protocol: Protocol,
    /// Destination port or range (None = any)
    pub port: Option<PortSpec>,
    /// Traffic direction
    pub direction: Direction,
    /// Action to take
    pub action: RuleAction,
    /// Rate limit policy (if action is RateLimit)
    pub rate_limit: Option<RateLimitPolicy>,
    /// Time-to-live (None = permanent)
    pub ttl: Option<Duration>,
    /// Human-readable comment
    pub comment: Option<String>,
    /// Priority (lower = higher priority)
    pub priority: u32,
}

impl FirewallRuleSpec {
    /// Create a simple block rule for an IP
    pub fn block_ip(ip: ValidatedIp) -> Self {
        Self {
            id: RuleId::generate(),
            source: Some(IpTarget::Single(ip)),
            destination: None,
            protocol: Protocol::All,
            port: None,
            direction: Direction::Inbound,
            action: RuleAction::Block,
            rate_limit: None,
            ttl: None,
            comment: Some(format!("Block IP {}", ip)),
            priority: 100,
        }
    }

    /// Create a rate limit rule for an IP
    pub fn rate_limit_ip(ip: ValidatedIp, policy: RateLimitPolicy) -> Self {
        Self {
            id: RuleId::generate(),
            source: Some(IpTarget::Single(ip)),
            destination: None,
            protocol: Protocol::All,
            port: None,
            direction: Direction::Inbound,
            action: RuleAction::RateLimit,
            rate_limit: Some(policy),
            ttl: None,
            comment: Some(format!("Rate limit IP {}", ip)),
            priority: 50, // Higher priority than block
        }
    }

    /// Set the TTL
    pub fn with_ttl(mut self, ttl: RuleTtl) -> Self {
        self.ttl = Some(ttl.duration());
        self
    }

    /// Set the comment
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Validate the rule specification
    pub fn validate(&self) -> FirewallResult<()> {
        // Validate rate limit if present
        if let Some(ref policy) = self.rate_limit {
            policy.validate()?;

            // Rate limit requires RateLimit action
            if self.action != RuleAction::RateLimit {
                return Err(FirewallError::InvalidRateLimit(
                    "Rate limit policy specified but action is not RateLimit".to_string(),
                ));
            }
        }

        // RateLimit action requires policy
        if self.action == RuleAction::RateLimit && self.rate_limit.is_none() {
            return Err(FirewallError::InvalidRateLimit(
                "RateLimit action requires a rate limit policy".to_string(),
            ));
        }

        // Validate port spec if present
        if let Some(ref port) = self.port {
            port.validate()?;
        }

        Ok(())
    }
}

/// IP target - single IP or CIDR block
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IpTarget {
    /// Single IP address
    Single(ValidatedIp),
    /// CIDR block
    Cidr(ValidatedCidr),
}

impl fmt::Display for IpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpTarget::Single(ip) => write!(f, "{}", ip),
            IpTarget::Cidr(cidr) => write!(f, "{}", cidr),
        }
    }
}

/// Port specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    /// Single port
    Single(u16),
    /// Port range (inclusive)
    Range {
        /// Start port
        start: u16,
        /// End port
        end: u16,
    },
    /// Multiple ports
    Multiple(Vec<u16>),
}

impl PortSpec {
    /// Validate the port specification
    pub fn validate(&self) -> FirewallResult<()> {
        match self {
            PortSpec::Single(p) => {
                if *p == 0 {
                    return Err(FirewallError::InvalidPort(0));
                }
            }
            PortSpec::Range { start, end } => {
                if *start == 0 {
                    return Err(FirewallError::InvalidPort(0));
                }
                if end < start {
                    return Err(FirewallError::InvalidPort(*end));
                }
            }
            PortSpec::Multiple(ports) => {
                for p in ports {
                    if *p == 0 {
                        return Err(FirewallError::InvalidPort(0));
                    }
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Operation Results
// ============================================================================

/// Result of a firewall operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    /// The rule ID affected
    pub rule_id: RuleId,
    /// Whether the operation made changes
    pub changed: bool,
    /// Human-readable message
    pub message: String,
    /// Previous state (for rollback)
    pub previous_state: Option<RuleState>,
}

impl OperationResult {
    /// Create a result for a new rule
    pub fn created(rule_id: RuleId) -> Self {
        Self {
            rule_id: rule_id.clone(),
            changed: true,
            message: format!("Rule {} created", rule_id),
            previous_state: None,
        }
    }

    /// Create a result for an already existing rule (idempotent)
    pub fn already_exists(rule_id: RuleId) -> Self {
        Self {
            rule_id: rule_id.clone(),
            changed: false,
            message: format!("Rule {} already exists", rule_id),
            previous_state: None,
        }
    }

    /// Create a result for a removed rule
    pub fn removed(rule_id: RuleId, previous: RuleState) -> Self {
        Self {
            rule_id: rule_id.clone(),
            changed: true,
            message: format!("Rule {} removed", rule_id),
            previous_state: Some(previous),
        }
    }

    /// Create a result for a not-found rule (idempotent removal)
    pub fn not_found(rule_id: RuleId) -> Self {
        Self {
            rule_id: rule_id.clone(),
            changed: false,
            message: format!("Rule {} not found", rule_id),
            previous_state: None,
        }
    }
}

/// State of a rule (for rollback)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleState {
    /// The full rule specification
    pub spec: FirewallRuleSpec,
    /// When the rule was created
    pub created_at: std::time::SystemTime,
    /// When the rule expires (if TTL set)
    pub expires_at: Option<std::time::SystemTime>,
}

// ============================================================================
// Rollback Types
// ============================================================================

/// A recorded action that can be rolled back
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedAction {
    /// Unique action ID
    pub action_id: String,
    /// Timestamp
    pub timestamp: std::time::SystemTime,
    /// The operation performed
    pub operation: RecordedOperation,
    /// The inverse operation (for rollback)
    pub inverse: RecordedOperation,
}

/// A recorded operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecordedOperation {
    /// Rule was added
    AddRule(FirewallRuleSpec),
    /// Rule was removed
    RemoveRule(RuleId, RuleState),
    /// Rule was modified
    ModifyRule {
        /// Rule identifier
        rule_id: RuleId,
        /// Previous rule state
        old_state: RuleState,
        /// New rule state
        new_state: RuleState,
    },
}

/// Result of a rollback operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    /// Number of actions rolled back
    pub actions_rolled_back: usize,
    /// Individual results
    pub results: Vec<OperationResult>,
    /// Any errors encountered (partial rollback)
    pub errors: Vec<String>,
}

// ============================================================================
// Backend Capability Discovery
// ============================================================================

/// Capabilities of a firewall backend
#[derive(Debug, Clone, Default)]
pub struct BackendCapabilities {
    /// Supports IPv4
    pub ipv4: bool,
    /// Supports IPv6
    pub ipv6: bool,
    /// Supports rate limiting
    pub rate_limiting: bool,
    /// Supports per-rule TTL
    pub ttl: bool,
    /// Supports logging
    pub logging: bool,
    /// Supports CIDR blocks
    pub cidr: bool,
    /// Supports port ranges
    pub port_ranges: bool,
    /// Supports rule priorities
    pub priorities: bool,
    /// Maximum rules supported (0 = unlimited)
    pub max_rules: usize,
    /// Backend name
    pub name: String,
    /// Backend version
    pub version: String,
}

// ============================================================================
// Firewall Backend Trait
// ============================================================================

/// Platform-specific firewall backend
///
/// Implementations:
/// - `IptablesBackend` - Linux iptables (legacy)
/// - `NftablesBackend` - Linux nftables (modern)
/// - `WindowsFirewallBackend` - Windows Firewall with Advanced Security
/// - `PfBackend` - BSD pf
/// - `MockBackend` - For testing
#[async_trait]
pub trait FirewallBackend: Send + Sync {
    /// Get backend capabilities
    fn capabilities(&self) -> &BackendCapabilities;

    /// Check if the backend is available and functional
    async fn health_check(&self) -> FirewallResult<()>;

    /// Add a firewall rule
    ///
    /// # Idempotency
    /// If an equivalent rule already exists, returns `Ok` with `changed: false`.
    async fn add_rule(&self, rule: &FirewallRuleSpec) -> FirewallResult<OperationResult>;

    /// Remove a firewall rule by ID
    ///
    /// # Idempotency
    /// If the rule doesn't exist, returns `Ok` with `changed: false`.
    async fn remove_rule(&self, rule_id: &RuleId) -> FirewallResult<OperationResult>;

    /// Check if a rule exists
    async fn rule_exists(&self, rule_id: &RuleId) -> FirewallResult<bool>;

    /// Get a rule by ID
    async fn get_rule(&self, rule_id: &RuleId) -> FirewallResult<Option<RuleState>>;

    /// List all rules managed by this backend
    async fn list_rules(&self) -> FirewallResult<Vec<RuleState>>;

    /// Find rules matching the given IP
    async fn find_rules_for_ip(&self, ip: &ValidatedIp) -> FirewallResult<Vec<RuleState>>;

    /// Flush all rules managed by this backend
    async fn flush_all(&self) -> FirewallResult<Vec<OperationResult>>;

    /// Get rule count
    async fn rule_count(&self) -> FirewallResult<usize>;
}

// ============================================================================
// High-Level Firewall Manager Trait
// ============================================================================

/// High-level firewall management interface
///
/// This trait provides the primary API for firewall operations,
/// with rollback support and TTL management.
#[async_trait]
pub trait FirewallManager: Send + Sync {
    // -------------------------------------------------------------------------
    // Core Operations
    // -------------------------------------------------------------------------

    /// Block an IP address
    ///
    /// Creates a rule to drop all inbound traffic from the specified IP.
    ///
    /// # Idempotency
    /// If the IP is already blocked, returns success without changes.
    async fn block_ip(&self, ip: ValidatedIp) -> FirewallResult<OperationResult>;

    /// Unblock an IP address
    ///
    /// Removes any block rules for the specified IP.
    ///
    /// # Idempotency
    /// If the IP is not blocked, returns success without changes.
    async fn unblock_ip(&self, ip: ValidatedIp) -> FirewallResult<OperationResult>;

    /// Block an IP with a time-to-live
    ///
    /// The block will automatically expire after the TTL.
    async fn block_ip_with_ttl(
        &self,
        ip: ValidatedIp,
        ttl: RuleTtl,
    ) -> FirewallResult<OperationResult>;

    /// Rate limit an IP address
    ///
    /// Applies rate limiting to traffic from the specified IP.
    async fn rate_limit_ip(
        &self,
        ip: ValidatedIp,
        policy: RateLimitPolicy,
    ) -> FirewallResult<OperationResult>;

    /// Remove rate limit from an IP
    async fn remove_rate_limit(&self, ip: ValidatedIp) -> FirewallResult<OperationResult>;

    // -------------------------------------------------------------------------
    // Rollback Operations
    // -------------------------------------------------------------------------

    /// Rollback the last N actions
    ///
    /// # Arguments
    /// * `count` - Number of actions to rollback (1 = last action only)
    ///
    /// # Returns
    /// Results of the rollback, including any partial failures.
    async fn rollback(&self, count: usize) -> FirewallResult<RollbackResult>;

    /// Get the number of actions available for rollback
    async fn rollback_available(&self) -> usize;

    /// Clear rollback history
    async fn clear_rollback_history(&self);

    // -------------------------------------------------------------------------
    // Query Operations
    // -------------------------------------------------------------------------

    /// Check if an IP is currently blocked
    async fn is_blocked(&self, ip: &ValidatedIp) -> FirewallResult<bool>;

    /// Check if an IP is currently rate limited
    async fn is_rate_limited(&self, ip: &ValidatedIp) -> FirewallResult<bool>;

    /// Get all blocked IPs
    async fn list_blocked_ips(&self) -> FirewallResult<Vec<ValidatedIp>>;

    /// Get all rate-limited IPs
    async fn list_rate_limited_ips(&self) -> FirewallResult<Vec<(ValidatedIp, RateLimitPolicy)>>;

    // -------------------------------------------------------------------------
    // Advanced Operations
    // -------------------------------------------------------------------------

    /// Add a custom rule
    async fn add_rule(&self, rule: FirewallRuleSpec) -> FirewallResult<OperationResult>;

    /// Remove a rule by ID
    async fn remove_rule(&self, rule_id: &RuleId) -> FirewallResult<OperationResult>;

    /// Block a CIDR range
    async fn block_cidr(&self, cidr: ValidatedCidr) -> FirewallResult<OperationResult>;

    /// Unblock a CIDR range
    async fn unblock_cidr(&self, cidr: ValidatedCidr) -> FirewallResult<OperationResult>;

    // -------------------------------------------------------------------------
    // Maintenance
    // -------------------------------------------------------------------------

    /// Process expired TTL rules
    ///
    /// Should be called periodically to clean up expired temporary rules.
    async fn process_expired_rules(&self) -> FirewallResult<Vec<OperationResult>>;

    /// Get backend capabilities
    fn capabilities(&self) -> &BackendCapabilities;

    /// Perform health check
    async fn health_check(&self) -> FirewallResult<()>;
}

// ============================================================================
// Builder Pattern for Rules
// ============================================================================

/// Builder for constructing firewall rules
#[derive(Debug, Default)]
pub struct RuleBuilder {
    source: Option<IpTarget>,
    destination: Option<IpTarget>,
    protocol: Protocol,
    port: Option<PortSpec>,
    direction: Direction,
    action: Option<RuleAction>,
    rate_limit: Option<RateLimitPolicy>,
    ttl: Option<Duration>,
    comment: Option<String>,
    priority: u32,
}

impl RuleBuilder {
    /// Create a new rule builder
    pub fn new() -> Self {
        Self {
            priority: 100,
            ..Default::default()
        }
    }

    /// Set the source IP
    pub fn source_ip(mut self, ip: ValidatedIp) -> Self {
        self.source = Some(IpTarget::Single(ip));
        self
    }

    /// Set the source CIDR
    pub fn source_cidr(mut self, cidr: ValidatedCidr) -> Self {
        self.source = Some(IpTarget::Cidr(cidr));
        self
    }

    /// Set the destination IP
    pub fn destination_ip(mut self, ip: ValidatedIp) -> Self {
        self.destination = Some(IpTarget::Single(ip));
        self
    }

    /// Set the protocol
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set a single destination port
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(PortSpec::Single(port));
        self
    }

    /// Set a port range
    pub fn port_range(mut self, start: u16, end: u16) -> Self {
        self.port = Some(PortSpec::Range { start, end });
        self
    }

    /// Set the direction
    pub fn direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Set action to block
    pub fn block(mut self) -> Self {
        self.action = Some(RuleAction::Block);
        self
    }

    /// Set action to allow
    pub fn allow(mut self) -> Self {
        self.action = Some(RuleAction::Allow);
        self
    }

    /// Set action to rate limit with policy
    pub fn rate_limit(mut self, policy: RateLimitPolicy) -> Self {
        self.action = Some(RuleAction::RateLimit);
        self.rate_limit = Some(policy);
        self
    }

    /// Set TTL
    pub fn ttl(mut self, ttl: RuleTtl) -> Self {
        self.ttl = Some(ttl.duration());
        self
    }

    /// Set comment
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set priority
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Build the rule
    pub fn build(self) -> FirewallResult<FirewallRuleSpec> {
        let action = self
            .action
            .ok_or_else(|| FirewallError::Internal("Action is required".to_string()))?;

        let rule = FirewallRuleSpec {
            id: RuleId::generate(),
            source: self.source,
            destination: self.destination,
            protocol: self.protocol,
            port: self.port,
            direction: self.direction,
            action,
            rate_limit: self.rate_limit,
            ttl: self.ttl,
            comment: self.comment,
            priority: self.priority,
        };

        rule.validate()?;
        Ok(rule)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validated_ip_creation() {
        // Valid IPs
        assert!(ValidatedIp::new("192.168.1.1".parse().unwrap()).is_ok());
        assert!(ValidatedIp::new("8.8.8.8".parse().unwrap()).is_ok());
        assert!(ValidatedIp::new("::1".parse().unwrap()).is_ok());

        // Invalid: unspecified
        assert!(ValidatedIp::new("0.0.0.0".parse().unwrap()).is_err());
        assert!(ValidatedIp::new("::".parse().unwrap()).is_err());

        // Invalid: broadcast
        assert!(ValidatedIp::new("255.255.255.255".parse().unwrap()).is_err());
    }

    #[test]
    fn test_validated_ip_from_str() {
        assert!("192.168.1.1".parse::<ValidatedIp>().is_ok());
        assert!("not-an-ip".parse::<ValidatedIp>().is_err());
        assert!("0.0.0.0".parse::<ValidatedIp>().is_err());
    }

    #[test]
    fn test_validated_cidr() {
        assert!(ValidatedCidr::new("192.168.1.0".parse().unwrap(), 24).is_ok());
        assert!(ValidatedCidr::new("10.0.0.0".parse().unwrap(), 8).is_ok());

        // Invalid prefix
        assert!(ValidatedCidr::new("192.168.1.0".parse().unwrap(), 33).is_err());
    }

    #[test]
    fn test_cidr_contains() {
        let cidr = ValidatedCidr::new("192.168.1.0".parse().unwrap(), 24).unwrap();
        
        let ip_in = ValidatedIp::new("192.168.1.100".parse().unwrap()).unwrap();
        let ip_out = ValidatedIp::new("192.168.2.1".parse().unwrap()).unwrap();

        assert!(cidr.contains(&ip_in));
        assert!(!cidr.contains(&ip_out));
    }

    #[test]
    fn test_rate_limit_policy_validation() {
        assert!(RateLimitPolicy::default().validate().is_ok());
        assert!(RateLimitPolicy::strict().validate().is_ok());

        let invalid = RateLimitPolicy {
            packets_per_second: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_rule_ttl() {
        assert!(RuleTtl::from_secs(60).is_ok());
        assert!(RuleTtl::from_hours(1).is_ok());

        // Too short
        assert!(RuleTtl::new(Duration::ZERO).is_err());

        // Too long (> 30 days)
        assert!(RuleTtl::new(Duration::from_secs(31 * 24 * 60 * 60)).is_err());
    }

    #[test]
    fn test_port_spec_validation() {
        assert!(PortSpec::Single(80).validate().is_ok());
        assert!(PortSpec::Single(0).validate().is_err());

        assert!(PortSpec::Range { start: 80, end: 443 }.validate().is_ok());
        assert!(PortSpec::Range { start: 443, end: 80 }.validate().is_err());
    }

    #[test]
    fn test_rule_builder() {
        let ip = "192.168.1.100".parse::<ValidatedIp>().unwrap();

        let rule = RuleBuilder::new()
            .source_ip(ip)
            .protocol(Protocol::Tcp)
            .port(80)
            .block()
            .comment("Block HTTP from suspicious IP")
            .build();

        assert!(rule.is_ok());
        let rule = rule.unwrap();
        assert_eq!(rule.action, RuleAction::Block);
        assert!(rule.comment.is_some());
    }

    #[test]
    fn test_rule_builder_rate_limit() {
        let ip = "10.0.0.5".parse::<ValidatedIp>().unwrap();

        let rule = RuleBuilder::new()
            .source_ip(ip)
            .rate_limit(RateLimitPolicy::strict())
            .ttl(RuleTtl::from_hours(1).unwrap())
            .build();

        assert!(rule.is_ok());
        let rule = rule.unwrap();
        assert_eq!(rule.action, RuleAction::RateLimit);
        assert!(rule.rate_limit.is_some());
        assert!(rule.ttl.is_some());
    }

    #[test]
    fn test_rule_spec_block_ip() {
        let ip = "8.8.8.8".parse::<ValidatedIp>().unwrap();
        let rule = FirewallRuleSpec::block_ip(ip);

        assert!(rule.validate().is_ok());
        assert_eq!(rule.action, RuleAction::Block);
        assert!(matches!(rule.source, Some(IpTarget::Single(_))));
    }

    #[test]
    fn test_firewall_rule_validation() {
        let ip = "192.168.1.1".parse::<ValidatedIp>().unwrap();

        // Valid block rule
        let rule = FirewallRuleSpec::block_ip(ip);
        assert!(rule.validate().is_ok());

        // Invalid: RateLimit action without policy
        let mut invalid_rule = rule.clone();
        invalid_rule.action = RuleAction::RateLimit;
        invalid_rule.rate_limit = None;
        assert!(invalid_rule.validate().is_err());
    }
}
