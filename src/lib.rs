//! WhiteQubit Agent Library
//!
//! Core library exposing the agent's public API and modules.
//!
//! # Architecture
//!
//! The agent is structured as a production-grade daemon with:
//!
//! - **Event Loop**: Async event processing with signal handling
//! - **State Machine**: Enforces valid state transitions
//! - **Write-Ahead Log**: Crash recovery and action journaling
//! - **Audit Logging**: Tamper-evident logging with hash chains
//! - **Privilege Separation**: Drops privileges after initialization
//! - **Sandboxing**: Linux-specific syscall and filesystem restrictions
//! - **Firewall Abstraction**: Platform-agnostic firewall management
//! - **Failure Handling**: Kill-switch, safe defaults, recovery coordination
//! - **Operator Alerting**: Real-time alerts and status reporting
//!
//! # Modules
//!
//! - [`actions`]: Security action definitions and execution
//! - [`audit`]: Append-only audit logging with integrity verification
//! - [`config`]: Configuration loading and validation
//! - [`core`]: Event loop, state machine, failure handling, and shutdown coordination
//! - [`events`]: Event sources and dispatching
//! - [`firewall`]: Platform-agnostic firewall abstraction layer
//! - [`observability`]: Metrics and health monitoring
//! - [`rollback`]: Write-ahead log and crash recovery
//! - [`security`]: Privilege management and sandboxing

#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

pub mod actions;
pub mod audit;
pub mod config;
pub mod core;
pub mod events;
pub mod firewall;
pub mod observability;
pub mod rollback;
pub mod security;

use thiserror::Error;

/// Result type for the agent
pub type Result<T> = std::result::Result<T, AgentError>;

/// Top-level error type for the agent
#[derive(Error, Debug)]
pub enum AgentError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    /// Core runtime error
    #[error("Core error: {0}")]
    Core(#[from] core::CoreError),

    /// Action execution error
    #[error("Action error: {0}")]
    Action(#[from] actions::ActionError),

    /// Rollback/journal error
    #[error("Rollback error: {0}")]
    Rollback(#[from] rollback::RollbackError),

    /// Audit logging error
    #[error("Audit error: {0}")]
    Audit(#[from] audit::AuditError),

    /// Event handling error
    #[error("Event error: {0}")]
    Event(#[from] events::EventError),

    /// Security/privilege error
    #[error("Security error: {0}")]
    Security(#[from] security::SecurityError),

    /// Failure handling error
    #[error("Failure error: {0}")]
    Failure(#[from] core::FailureError),

    /// Alerting error
    #[error("Alert error: {0}")]
    Alert(#[from] core::AlertError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
