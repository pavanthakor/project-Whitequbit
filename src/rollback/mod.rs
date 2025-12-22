//! Rollback module - Write-ahead log and crash recovery
//!
//! Ensures atomic action execution with guaranteed rollback capability.

mod checkpoint;
mod compensator;
pub mod firewall_rollback;
mod journal;
mod recovery;

pub use checkpoint::{Checkpoint, CheckpointManager};
pub use compensator::Compensator;
pub use firewall_rollback::{
    FirewallRuleRecord, RemovalReason, RollbackEngine, RollbackEngineConfig,
    RollbackEngineError, RollbackId, RollbackResult, RollbackScope, RuleRecordState,
    RuleRegistry, RuleRollbackResult,
};
pub use journal::{Journal, JournalEntry, JournalEntryId, JournalEntryState};
pub use recovery::RecoveryManager;

use thiserror::Error;

/// Errors from rollback operations
#[derive(Error, Debug)]
pub enum RollbackError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Corruption detected
    #[error("Data corruption detected: {0}")]
    Corruption(String),

    /// Entry not found
    #[error("Journal entry not found: {0}")]
    EntryNotFound(String),

    /// Invalid state transition
    #[error("Invalid journal state transition: {from:?} -> {to:?}")]
    InvalidStateTransition {
        /// Source state
        from: JournalEntryState,
        /// Target state
        to: JournalEntryState,
    },

    /// Recovery failed
    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    /// Lock error
    #[error("Failed to acquire lock: {0}")]
    Lock(String),
}
