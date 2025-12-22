//! Event Source - Core event abstraction
//!
//! Defines the Event type and EventSource trait.

use std::fmt::Debug;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::actions::{Action, ActionError};

/// Unique identifier for an event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(Uuid);

impl EventId {
    /// Get as u128
    pub fn as_u128(&self) -> u128 {
        self.0.as_u128()
    }
    
    /// Create a new random event ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from a UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Event priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventPriority {
    /// Low priority event
    Low,
    /// Normal priority event
    Normal,
    /// High priority event
    High,
    /// Critical priority event
    Critical,
}

impl Default for EventPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Event type categories
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Firewall-related event
    Firewall(FirewallEventType),
    /// Service-related event
    Service(ServiceEventType),
    /// System event
    System(SystemEventType),
    /// Custom event type
    Custom(String),
}

/// Firewall event types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallEventType {
    /// Block an IP address
    BlockIp,
    /// Unblock an IP address
    UnblockIp,
    /// Add a firewall rule
    AddRule,
    /// Remove a firewall rule
    RemoveRule,
    /// Flush a firewall chain
    FlushChain,
}

/// Service event types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceEventType {
    /// Start a service
    Start,
    /// Stop a service
    Stop,
    /// Restart a service
    Restart,
    /// Enable a service
    Enable,
    /// Disable a service
    Disable,
}

/// System event types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemEventType {
    /// Shutdown the agent
    Shutdown,
    /// Reload configuration
    Reload,
    /// Status query
    Status,
    /// Health check
    HealthCheck,
    /// Config reload
    ConfigReload,
    /// Heartbeat signal
    Heartbeat,
}

/// Client information for the event source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client identifier
    pub id: String,
    /// Principal (identity) of the client
    pub principal: String,
    /// Process ID (for local clients)
    pub pid: Option<u32>,
    /// User ID (for local clients)
    pub uid: Option<u32>,
    /// Group ID (for local clients)
    pub gid: Option<u32>,
    /// Remote address (for network clients)
    pub remote_addr: Option<String>,
}

/// An event from any event source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unique event ID
    id: EventId,
    /// Event type
    event_type: EventType,
    /// Event priority
    priority: EventPriority,
    /// When the event was received
    received_at: DateTime<Utc>,
    /// Client that sent the event
    client: Option<ClientInfo>,
    /// Event payload
    payload: serde_json::Value,
    /// Correlation ID for tracking related events
    correlation_id: Option<String>,
}

impl Event {
    /// Create a new event
    pub fn new(event_type: EventType, payload: serde_json::Value) -> Self {
        Self {
            id: EventId::new(),
            event_type,
            priority: EventPriority::default(),
            received_at: Utc::now(),
            client: None,
            payload,
            correlation_id: None,
        }
    }

    /// Get the event ID
    pub fn id(&self) -> EventId {
        self.id
    }

    /// Get the event type as a string
    pub fn event_type(&self) -> String {
        match &self.event_type {
            EventType::Firewall(ft) => format!("firewall.{:?}", ft).to_lowercase(),
            EventType::Service(st) => format!("service.{:?}", st).to_lowercase(),
            EventType::System(st) => format!("system.{:?}", st).to_lowercase(),
            EventType::Custom(s) => format!("custom.{}", s),
        }
    }

    /// Get the event type enum
    pub fn event_type_enum(&self) -> &EventType {
        &self.event_type
    }

    /// Set priority
    pub fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set client info
    pub fn with_client(mut self, client: ClientInfo) -> Self {
        self.client = Some(client);
        self
    }

    /// Set correlation ID
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Get the priority
    pub fn priority(&self) -> EventPriority {
        self.priority
    }

    /// Get client info
    pub fn client(&self) -> Option<&ClientInfo> {
        self.client.as_ref()
    }

    /// Get the payload
    pub fn payload(&self) -> &serde_json::Value {
        &self.payload
    }

    /// Convert the event to an action
    pub fn to_action(&self) -> Result<Box<dyn Action>, ActionError> {
        use crate::actions::{
            FirewallAction, FirewallOperation,
            ServiceAction, ServiceOperation,
        };

        match &self.event_type {
            EventType::Firewall(ft) => {
                let rule = self.parse_firewall_rule()?;
                let operation = match ft {
                    FirewallEventType::BlockIp | FirewallEventType::AddRule => FirewallOperation::Add,
                    FirewallEventType::UnblockIp | FirewallEventType::RemoveRule => FirewallOperation::Remove,
                    FirewallEventType::FlushChain => FirewallOperation::Flush,
                };
                Ok(Box::new(FirewallAction::new(operation, rule)))
            }
            EventType::Service(st) => {
                let service_name = self.payload["service"]
                    .as_str()
                    .ok_or_else(|| ActionError::Validation(
                        crate::actions::ValidationError::MissingField("service".to_string())
                    ))?;

                let operation = match st {
                    ServiceEventType::Start => ServiceOperation::Start,
                    ServiceEventType::Stop => ServiceOperation::Stop,
                    ServiceEventType::Restart => ServiceOperation::Restart,
                    ServiceEventType::Enable => ServiceOperation::Enable,
                    ServiceEventType::Disable => ServiceOperation::Disable,
                };

                Ok(Box::new(ServiceAction::new(service_name, operation)))
            }
            EventType::System(_) => {
                Err(ActionError::UnknownAction("system events are handled internally".to_string()))
            }
            EventType::Custom(name) => {
                Err(ActionError::UnknownAction(format!("custom event: {}", name)))
            }
        }
    }

    /// Parse firewall rule from payload
    fn parse_firewall_rule(&self) -> Result<crate::actions::FirewallRule, ActionError> {
        use crate::actions::{Direction, FirewallRule, Protocol, RuleTarget};

        let source = self.payload["source"].as_str().map(String::from);
        let destination = self.payload["destination"].as_str().map(String::from);

        let protocol = match self.payload["protocol"].as_str() {
            Some("tcp") => Protocol::Tcp,
            Some("udp") => Protocol::Udp,
            Some("icmp") => Protocol::Icmp,
            _ => Protocol::All,
        };

        let port = self.payload["port"].as_u64().map(|p| p as u16);

        let direction = match self.payload["direction"].as_str() {
            Some("output") => Direction::Output,
            Some("forward") => Direction::Forward,
            _ => Direction::Input,
        };

        let target = match self.payload["target"].as_str() {
            Some("ACCEPT") => RuleTarget::Accept,
            Some("REJECT") => RuleTarget::Reject,
            Some("LOG") => RuleTarget::Log,
            _ => RuleTarget::Drop,
        };

        Ok(FirewallRule {
            source,
            destination,
            protocol,
            port,
            port_end: None,
            direction,
            target,
            comment: self.payload["comment"].as_str().map(String::from),
        })
    }
}

/// Trait for event sources
#[allow(dead_code)]
#[async_trait::async_trait]
pub trait EventSource: Send + Sync {
    /// Get the next event from this source
    async fn next_event(&mut self) -> Option<Event>;

    /// Shutdown the event source
    async fn shutdown(&mut self);

    /// Get the source name
    fn name(&self) -> &str;
}
