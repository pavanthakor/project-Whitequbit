//! Firewall Actions - Firewall rule management
//!
//! Supports adding, removing, and modifying firewall rules with rollback.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::info;

use super::action::{Action, ActionId, ActionResult, ExecutionContext, ValidationError};
use super::privileged_executor::{Capability, CapabilitySet};
use super::ActionError;

/// Firewall rule protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
    /// ICMP protocol
    Icmp,
    /// All protocols
    All,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::All => write!(f, "all"),
        }
    }
}

/// Firewall rule target action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuleTarget {
    /// Accept the packet
    Accept,
    /// Drop the packet silently
    Drop,
    /// Reject the packet with response
    Reject,
    /// Log the packet
    Log,
}

impl std::fmt::Display for RuleTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleTarget::Accept => write!(f, "ACCEPT"),
            RuleTarget::Drop => write!(f, "DROP"),
            RuleTarget::Reject => write!(f, "REJECT"),
            RuleTarget::Log => write!(f, "LOG"),
        }
    }
}

/// Firewall rule direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Incoming traffic
    Input,
    /// Outgoing traffic
    Output,
    /// Forwarded traffic
    Forward,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::Input => write!(f, "INPUT"),
            Direction::Output => write!(f, "OUTPUT"),
            Direction::Forward => write!(f, "FORWARD"),
        }
    }
}

/// A firewall rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Source IP address or CIDR
    pub source: Option<String>,
    /// Destination IP address or CIDR
    pub destination: Option<String>,
    /// Protocol
    pub protocol: Protocol,
    /// Destination port (for TCP/UDP)
    pub port: Option<u16>,
    /// Port range end (for port ranges)
    pub port_end: Option<u16>,
    /// Chain/direction
    pub direction: Direction,
    /// Target action
    pub target: RuleTarget,
    /// Comment/description
    pub comment: Option<String>,
}

impl FirewallRule {
    /// Create a new rule to block an IP
    pub fn block_ip(ip: IpAddr) -> Self {
        Self {
            source: Some(ip.to_string()),
            destination: None,
            protocol: Protocol::All,
            port: None,
            port_end: None,
            direction: Direction::Input,
            target: RuleTarget::Drop,
            comment: Some(format!("Block IP {}", ip)),
        }
    }

    /// Create a new rule to allow a port
    pub fn allow_port(port: u16, protocol: Protocol) -> Self {
        Self {
            source: None,
            destination: None,
            protocol,
            port: Some(port),
            port_end: None,
            direction: Direction::Input,
            target: RuleTarget::Accept,
            comment: Some(format!("Allow {} port {}", protocol, port)),
        }
    }

    /// Validate the rule
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Validate port for non-port protocols
        if matches!(self.protocol, Protocol::Icmp | Protocol::All) && self.port.is_some() {
            return Err(ValidationError::InvalidValue {
                field: "port".to_string(),
                reason: format!("Port not applicable for {} protocol", self.protocol),
            });
        }

        // Validate port range
        if let (Some(start), Some(end)) = (self.port, self.port_end) {
            if end <= start {
                return Err(ValidationError::InvalidValue {
                    field: "port_end".to_string(),
                    reason: "Port range end must be greater than start".to_string(),
                });
            }
        }

        // Validate CIDR notation if present
        if let Some(ref source) = self.source {
            Self::validate_ip_or_cidr(source)?;
        }
        if let Some(ref dest) = self.destination {
            Self::validate_ip_or_cidr(dest)?;
        }

        Ok(())
    }

    fn validate_ip_or_cidr(value: &str) -> Result<(), ValidationError> {
        // Simple validation - in production, use a proper IP/CIDR parser
        if value.contains('/') {
            let parts: Vec<&str> = value.split('/').collect();
            if parts.len() != 2 {
                return Err(ValidationError::InvalidValue {
                    field: "ip".to_string(),
                    reason: format!("Invalid CIDR notation: {}", value),
                });
            }
        }
        Ok(())
    }
}

/// Firewall action operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallOperation {
    /// Add a new rule
    Add,
    /// Remove an existing rule
    Remove,
    /// Insert a rule at a specific position
    Insert,
    /// Flush all rules in a chain
    Flush,
}

/// Firewall action - manages firewall rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallAction {
    /// Unique action ID
    id: ActionId,
    /// Operation to perform
    pub operation: FirewallOperation,
    /// The rule to add/remove
    pub rule: FirewallRule,
    /// Position for insert operations
    pub position: Option<u32>,
    /// Table name (filter, nat, mangle)
    pub table: String,
}

impl FirewallAction {
    /// Create a new firewall action
    pub fn new(operation: FirewallOperation, rule: FirewallRule) -> Self {
        Self {
            id: ActionId::new(),
            operation,
            rule,
            position: None,
            table: "filter".to_string(),
        }
    }

    /// Create action with specific ID (for deserialization)
    pub fn with_id(id: ActionId, operation: FirewallOperation, rule: FirewallRule) -> Self {
        Self {
            id,
            operation,
            rule,
            position: None,
            table: "filter".to_string(),
        }
    }

    /// Set the table
    pub fn table(mut self, table: impl Into<String>) -> Self {
        self.table = table.into();
        self
    }

    /// Set position for insert
    pub fn at_position(mut self, position: u32) -> Self {
        self.position = Some(position);
        self
    }

    /// Build the iptables command
    fn build_command(&self) -> Vec<String> {
        let mut args = vec!["iptables".to_string()];

        // Table
        args.extend(["-t".to_string(), self.table.clone()]);

        // Operation
        match self.operation {
            FirewallOperation::Add => args.push("-A".to_string()),
            FirewallOperation::Remove => args.push("-D".to_string()),
            FirewallOperation::Insert => {
                args.push("-I".to_string());
            }
            FirewallOperation::Flush => {
                args.push("-F".to_string());
                args.push(self.rule.direction.to_string());
                return args;
            }
        }

        // Chain
        args.push(self.rule.direction.to_string());

        // Position for insert
        if let Some(pos) = self.position {
            if self.operation == FirewallOperation::Insert {
                args.push(pos.to_string());
            }
        }

        // Protocol
        if !matches!(self.rule.protocol, Protocol::All) {
            args.extend(["-p".to_string(), self.rule.protocol.to_string()]);
        }

        // Source
        if let Some(ref source) = self.rule.source {
            args.extend(["-s".to_string(), source.clone()]);
        }

        // Destination
        if let Some(ref dest) = self.rule.destination {
            args.extend(["-d".to_string(), dest.clone()]);
        }

        // Port
        if let Some(port) = self.rule.port {
            args.push("--dport".to_string());
            if let Some(end_port) = self.rule.port_end {
                args.push(format!("{}:{}", port, end_port));
            } else {
                args.push(port.to_string());
            }
        }

        // Target
        args.extend(["-j".to_string(), self.rule.target.to_string()]);

        // Comment
        if let Some(ref comment) = self.rule.comment {
            args.extend([
                "-m".to_string(),
                "comment".to_string(),
                "--comment".to_string(),
                comment.clone(),
            ]);
        }

        args
    }
}

impl Action for FirewallAction {
    fn id(&self) -> ActionId {
        self.id
    }

    fn action_type(&self) -> &'static str {
        "firewall"
    }

    fn validate(&self) -> Result<(), ValidationError> {
        self.rule.validate()
    }

    fn execute(&self, ctx: &ExecutionContext) -> Result<ActionResult, ActionError> {
        let command = self.build_command();
        info!("Executing firewall command: {:?}", command);

        if ctx.dry_run {
            return Ok(ActionResult::no_change(format!(
                "Dry run: would execute {:?}",
                command
            )));
        }

        // Execute the iptables command
        #[cfg(unix)]
        {
            let output = std::process::Command::new(&command[0])
                .args(&command[1..])
                .output()
                .map_err(|e| ActionError::Execution(format!("Failed to execute iptables: {}", e)))?;

            if output.status.success() {
                Ok(ActionResult::changed(format!(
                    "Firewall rule {:?} completed",
                    self.operation
                )))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                Err(ActionError::Execution(format!(
                    "iptables failed: {}",
                    stderr
                )))
            }
        }

        #[cfg(not(unix))]
        {
            Err(ActionError::Execution(
                "Firewall actions only supported on Unix".to_string(),
            ))
        }
    }

    fn compensation(&self) -> Box<dyn Action> {
        // The inverse operation
        let inverse_op = match self.operation {
            FirewallOperation::Add => FirewallOperation::Remove,
            FirewallOperation::Remove => FirewallOperation::Add,
            FirewallOperation::Insert => FirewallOperation::Remove,
            FirewallOperation::Flush => {
                // Flush is not reversible without storing state
                // In production, we'd save the rules before flush
                FirewallOperation::Flush
            }
        };

        Box::new(FirewallAction::with_id(
            ActionId::new(), // New ID for compensation
            inverse_op,
            self.rule.clone(),
        ))
    }

    fn serialize(&self) -> Result<Vec<u8>, ActionError> {
        serde_json::to_vec(self).map_err(|e| ActionError::Serialization(e.to_string()))
    }

    fn description(&self) -> String {
        format!(
            "{:?} firewall rule: {} {} {:?}",
            self.operation,
            self.rule.direction,
            self.rule.target,
            self.rule.source.as_deref().unwrap_or("any")
        )
    }

    fn estimated_duration(&self) -> Duration {
        Duration::from_millis(500)
    }

    fn required_capabilities(&self) -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        // All firewall operations require CAP_NET_ADMIN
        caps.insert(Capability::NetAdmin);
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_ip_rule() {
        let rule = FirewallRule::block_ip("192.168.1.100".parse().unwrap());
        assert_eq!(rule.source, Some("192.168.1.100".to_string()));
        assert_eq!(rule.target, RuleTarget::Drop);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_action_command_building() {
        let rule = FirewallRule::allow_port(443, Protocol::Tcp);
        let action = FirewallAction::new(FirewallOperation::Add, rule);
        let cmd = action.build_command();

        assert!(cmd.contains(&"-A".to_string()));
        assert!(cmd.contains(&"INPUT".to_string()));
        assert!(cmd.contains(&"-p".to_string()));
        assert!(cmd.contains(&"tcp".to_string()));
        assert!(cmd.contains(&"--dport".to_string()));
        assert!(cmd.contains(&"443".to_string()));
    }

    #[test]
    fn test_compensation() {
        let rule = FirewallRule::block_ip("10.0.0.1".parse().unwrap());
        let action = FirewallAction::new(FirewallOperation::Add, rule);

        // Verify the action validates
        assert!(action.validate().is_ok());

        // The compensation should be a remove action
        let comp = action.compensation();
        assert_eq!(comp.action_type(), "firewall");
    }
}
