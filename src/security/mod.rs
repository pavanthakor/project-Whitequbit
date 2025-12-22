//! Security module - Privilege management and sandboxing
//!
//! Handles privilege dropping, capability management, and sandbox application.

mod auth;
mod policy;
mod privileges;
mod sandbox;

pub use auth::{AuthManager, ClientAuth};
pub use policy::{Policy, PolicyEngine};
pub use privileges::PrivilegeManager;
pub use sandbox::{SandboxManager, SandboxConfig};

use thiserror::Error;

/// Errors from security operations
#[derive(Error, Debug)]
pub enum SecurityError {
    /// Privilege operation failed
    #[error("Privilege error: {0}")]
    Privilege(String),

    /// Sandbox error
    #[error("Sandbox error: {0}")]
    Sandbox(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authorization denied
    #[error("Authorization denied: {0}")]
    Authorization(String),

    /// Policy error
    #[error("Policy error: {0}")]
    Policy(String),

    /// System error
    #[error("System error: {0}")]
    System(#[from] std::io::Error),
}
