//! Action trait - Core abstraction for executable security actions
//!
//! Every action must be able to execute, rollback, and serialize itself.

use std::fmt::Debug;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use super::privileged_executor::CapabilitySet;

/// Unique identifier for an action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(Uuid);

impl ActionId {
    /// Create a new random action ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an action ID from a UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for ActionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validation error for actions
#[derive(Error, Debug)]
pub enum ValidationError {
    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid field value
    #[error("Invalid value for {field}: {reason}")]
    InvalidValue {
        /// Field name
        field: String,
        /// Error reason
        reason: String,
    },

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
}

/// Result of a successful action execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// Whether the action made changes
    pub changed: bool,
    /// Human-readable message
    pub message: String,
    /// Additional data returned by the action
    pub data: serde_json::Value,
}

impl ActionResult {
    /// Create a result indicating changes were made
    pub fn changed(message: impl Into<String>) -> Self {
        Self {
            changed: true,
            message: message.into(),
            data: serde_json::Value::Null,
        }
    }

    /// Create a result indicating no changes
    pub fn unchanged(message: impl Into<String>) -> Self {
        Self {
            changed: false,
            message: message.into(),
            data: serde_json::Value::Null,
        }
    }

    /// Alias for unchanged - no changes made
    pub fn no_change(message: impl Into<String>) -> Self {
        Self::unchanged(message)
    }

    /// Add data to the result
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = data;
        self
    }

    /// Create a result indicating the action was skipped
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            changed: false,
            message: format!("Skipped: {}", reason.into()),
            data: serde_json::json!({"status": "skipped"}),
        }
    }

    /// Create a result indicating the action was deferred
    pub fn deferred(reason: impl Into<String>) -> Self {
        Self {
            changed: false,
            message: format!("Deferred: {}", reason.into()),
            data: serde_json::json!({"status": "deferred"}),
        }
    }
}

/// Core trait for all security actions
///
/// Actions must be:
/// - Executable (make changes to the system)
/// - Rollbackable (undo changes)
/// - Validatable (check preconditions)
/// - Serializable (for persistence)
pub trait Action: Debug + Send + Sync {
    /// Get the action ID
    fn id(&self) -> ActionId;

    /// Get the action type name
    fn action_type(&self) -> &'static str;

    /// Validate the action before execution
    fn validate(&self) -> Result<(), ValidationError>;

    /// Execute the action
    fn execute(&self, ctx: &ExecutionContext) -> Result<ActionResult, super::ActionError>;

    /// Get the compensation action (inverse operation)
    fn compensation(&self) -> Box<dyn Action>;

    /// Serialize the action to bytes
    fn serialize(&self) -> Result<Vec<u8>, super::ActionError>;

    /// Get a human-readable description
    fn description(&self) -> String;

    /// Get the estimated execution duration
    fn estimated_duration(&self) -> Duration {
        Duration::from_secs(5)
    }

    /// Get the execution timeout
    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    /// Check if this action requires elevated privileges
    fn requires_privilege(&self) -> bool {
        true
    }

    /// Get the capabilities required by this action
    fn required_capabilities(&self) -> CapabilitySet {
        CapabilitySet::new()
    }

    /// Get serialized action data as JSON
    fn to_json(&self) -> serde_json::Value {
        self.serialize()
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(serde_json::Value::Null)
    }

    /// Roll back the action (undo changes) - default uses compensation
    fn rollback(&self, ctx: &ExecutionContext) -> Result<ActionResult, super::ActionError> {
        self.compensation().execute(ctx)
    }
}

/// Execution context for actions
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Action ID
    pub action_id: ActionId,
    /// Dry run mode
    pub dry_run: bool,
    /// Timeout override
    pub timeout: Option<Duration>,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self {
            action_id: ActionId::new(),
            dry_run: false,
            timeout: None,
        }
    }
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(action_id: ActionId) -> Self {
        Self {
            action_id,
            dry_run: false,
            timeout: None,
        }
    }

    /// Create a dry-run context
    pub fn dry_run(action_id: ActionId) -> Self {
        Self {
            action_id,
            dry_run: true,
            timeout: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_id_display() {
        let id = ActionId::new();
        let display = format!("{}", id);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_action_result() {
        let result = ActionResult::changed("Test completed")
            .with_data(serde_json::json!({"key": "value"}));

        assert!(result.changed);
        assert_eq!(result.message, "Test completed");
    }
}
