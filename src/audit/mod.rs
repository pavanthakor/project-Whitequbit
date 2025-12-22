//! Audit module - Immutable logging and integrity verification
//!
//! Provides tamper-evident audit logging with hash chains, crash-safe writes,
//! and before/after state capture for security operations.
//!
//! # Modules
//!
//! - `immutable`: Production-grade immutable audit log with WAL
//! - `logger`: Basic audit logger with hash chaining
//! - `integrity`: Verification utilities
//! - `sink`: Output destinations (file, syslog)

pub mod immutable;
mod integrity;
mod logger;
mod sink;

pub use integrity::{IntegrityVerifier, VerificationResult};
pub use logger::{AuditEntry, AuditEventType, AuditLogger};
pub use sink::{AuditSinkType, FileSink, MultiSink, SyslogSink};

// Re-export immutable audit types
pub use immutable::{
    // Core types
    ImmutableAuditLogger, ImmutableAuditConfig, ImmutableAuditEntry,
    ImmutableAuditError, ImmutableAuditResult,
    // Entry building
    AuditEntryBuilder, AuditCategory, AuditSeverity, AuditOutcome,
    // Actor/Target
    AuditActor, AuditTarget,
    // State capture
    StateSnapshot, StateTransition,
    // Verification
    VerificationResult as ImmutableVerificationResult,
    // Metrics
    AuditMetrics,
};

use thiserror::Error;

/// Errors from audit operations
#[derive(Error, Debug)]
pub enum AuditError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Integrity verification failed
    #[error("Integrity check failed: {0}")]
    IntegrityFailed(String),

    /// Sink error
    #[error("Audit sink error: {0}")]
    Sink(String),
}
