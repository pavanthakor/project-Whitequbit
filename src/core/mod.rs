//! Core module - Agent runtime components
//!
//! Contains the event loop, supervisor integration, state machine,
//! shutdown coordination, failure handling, and operator alerting.

pub mod alerting;
mod event_loop;
pub mod failure;
mod shutdown;
mod state_machine;
pub mod startup;
mod supervisor;

pub use alerting::{
    Alert, AlertError, AlertManager, AlertPriority, AlertResult, AgentStatus,
    ConfigStatus, HealthStatus, InterventionRequest, InterventionType, StatusReporter,
};
pub use event_loop::{EventLoop, EventLoopBuilder};
pub use failure::{
    CircuitBreaker, CircuitState, ConfigValidationResult, ConfigValidator,
    DefaultFailureHandler, FailureAction, FailureCategory, FailureError,
    FailureHandler, FailureRecord, FailureResult, InFlightAction, InFlightTracker,
    KillSwitch, KillSwitchState, RecoveryCoordinator, SafeDefaults, StartupRecoveryResult,
    ActionPhase, FailureSeverity, FirewallDefaults, DefaultPolicy, AllowedPort,
};
pub use shutdown::ShutdownCoordinator;
pub use state_machine::{AgentState, StateMachine};
pub use startup::{StartupChecker, StartupCheckResult, run_startup_checks};
pub use supervisor::SupervisorClient;

use thiserror::Error;

/// Errors from core runtime operations
#[derive(Error, Debug)]
pub enum CoreError {
    /// Invalid state transition
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// The state we were transitioning from
        from: AgentState,
        /// The state we were trying to transition to
        to: AgentState,
    },

    /// Event loop error
    #[error("Event loop error: {0}")]
    EventLoop(String),

    /// Supervisor communication error
    #[error("Supervisor error: {0}")]
    Supervisor(String),

    /// Shutdown requested
    #[error("Shutdown requested")]
    Shutdown,

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Startup check failure
    #[error("Startup check failed: {0}")]
    StartupCheck(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}
