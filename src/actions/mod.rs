//! Actions module - Security action definitions and execution
//!
//! Each action is self-contained with execute and rollback capabilities.

pub mod action;
mod executor;
mod firewall;
pub mod privileged_executor;
mod registry;
mod services;

pub use action::{Action, ActionId, ActionResult, ValidationError, ExecutionContext};
pub use executor::ActionExecutor;
pub use firewall::{FirewallAction, FirewallRule, FirewallOperation, Protocol, RuleTarget, Direction};
pub use privileged_executor::{
    Capability, CapabilitySet, PrivilegedExecutor, PrivilegeFailurePolicy,
    validate_executable, sanitize_argument, ALLOWED_EXECUTABLES,
};
pub use registry::ActionRegistry;
pub use services::{ServiceAction, ServiceOperation};

use thiserror::Error;

/// Errors from action operations
#[derive(Error, Debug)]
pub enum ActionError {
    /// Action validation failed
    #[error("Validation failed: {0}")]
    Validation(#[from] ValidationError),

    /// Action execution failed
    #[error("Execution failed: {0}")]
    Execution(String),

    /// Action not found in registry
    #[error("Unknown action type: {0}")]
    UnknownAction(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Sandbox error
    #[error("Sandbox error: {0}")]
    Sandbox(String),

    /// Timeout during execution
    #[error("Action timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Insufficient privilege/capabilities
    #[error("Insufficient privilege: {0}")]
    InsufficientPrivilege(String),
}
