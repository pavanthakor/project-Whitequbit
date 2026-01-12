//! Recovery Manager - Crash recovery logic
//!
//! Handles recovery from crashes by processing uncommitted WAL entries.

use std::path::{Path, PathBuf};
use std::sync::Arc;



use super::checkpoint::CheckpointManager;
use super::compensator::Compensator;
use super::journal::Journal;
use super::RollbackError;

/// Result of a recovery operation
#[derive(Debug)]
pub struct RecoveryResult {
    /// Number of entries recovered
    pub entries_recovered: usize,
    /// Number of entries that failed to recover
    pub entries_failed: usize,
    /// Whether any manual intervention is required
    pub requires_intervention: bool,
    /// Details about failed entries
    pub failed_details: Vec<String>,
}

impl RecoveryResult {
    /// Create a successful result
    pub fn success(entries_recovered: usize) -> Self {
        Self {
            entries_recovered,
            entries_failed: 0,
            requires_intervention: false,
            failed_details: Vec::new(),
        }
    }

    /// Create a partial failure result
    pub fn partial(
        entries_recovered: usize,
        entries_failed: usize,
        failed_details: Vec<String>,
    ) -> Self {
        Self {
            entries_recovered,
            entries_failed,
            requires_intervention: entries_failed > 0,
            failed_details,
        }
    }

    /// Check if recovery was completely successful
    pub fn is_complete(&self) -> bool {
        self.entries_failed == 0
    }
}

/// Manager for crash recovery
pub struct RecoveryManager {
    /// Journal for WAL operations
    journal: Arc<Journal>,
    /// Compensator for executing rollbacks
    compensator: Compensator,
    /// Optional checkpoint directory
    checkpoint_dir: Option<PathBuf>,
}

impl RecoveryManager {
    /// Create a new recovery manager
    pub fn new(journal: Arc<Journal>) -> Self {
        Self {
            journal,
            compensator: Compensator::new(),
            checkpoint_dir: None,
        }
    }

    /// Create from a WAL path
    pub fn from_path(wal_path: impl AsRef<Path>) -> Result<Self, RollbackError> {
        let journal = Journal::new(wal_path)?;
        Ok(Self::new(Arc::new(journal)))
    }

    /// Set the compensator
    pub fn with_compensator(mut self, compensator: Compensator) -> Self {
        self.compensator = compensator;
        self
    }

    /// Set checkpoint directory
    pub fn with_checkpoints(mut self, dir: impl AsRef<Path>) -> Self {
        self.checkpoint_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Check if recovery is needed
    pub async fn needs_recovery(&self) -> Result<bool, RollbackError> {
        let uncommitted = self.journal.get_uncommitted().await;
        Ok(!uncommitted.is_empty())
    }

    /// Get count of uncommitted entries
    pub async fn uncommitted_count(&self) -> usize {
        self.journal.get_uncommitted().await.len()
    }

    /// Perform crash recovery
    pub async fn recover(&self) -> Result<RecoveryResult, RollbackError> {
        tracing::info!("Starting crash recovery");

        // Get uncommitted entries
        let uncommitted = self.journal.get_uncommitted().await;

        if uncommitted.is_empty() {
            tracing::info!("No uncommitted entries found, no recovery needed");
            return Ok(RecoveryResult::success(0));
        }

        let total = uncommitted.len();
        tracing::warn!("Found {} uncommitted entries, initiating rollback", total);

        // Execute compensations
        let results = self.compensator.compensate_all(uncommitted).await;

        // Process results
        let mut recovered = 0;
        let mut failed_details = Vec::new();

        for result in &results {
            if result.success {
                // Mark as rolled back in journal
                if let Err(e) = self.journal.mark_rolled_back(result.entry_id).await {
                    tracing::warn!("Failed to mark entry {} as rolled back: {}", result.entry_id, e);
                }
                recovered += 1;
            } else {
                // Mark as rollback failed
                if let Err(e) = self.journal.mark_rollback_failed(result.entry_id).await {
                    tracing::warn!("Failed to mark entry {} as rollback failed: {}", result.entry_id, e);
                }

                let detail = format!(
                    "Entry {}: {}",
                    result.entry_id,
                    result.error.as_deref().unwrap_or("Unknown error")
                );
                failed_details.push(detail);
            }
        }

        let failed = failed_details.len();

        if failed > 0 {
            tracing::error!(
                "Recovery completed with {} failures requiring intervention",
                failed
            );
            Ok(RecoveryResult::partial(recovered, failed, failed_details))
        } else {
            tracing::info!("Recovery completed successfully: {} entries recovered", recovered);
            Ok(RecoveryResult::success(recovered))
        }
    }

    /// Restore from checkpoint (if available)
    pub async fn restore_checkpoint(&self) -> Result<Option<PathBuf>, RollbackError> {
        let checkpoint_dir = match &self.checkpoint_dir {
            Some(dir) => dir,
            None => {
                tracing::info!("No checkpoint directory configured");
                return Ok(None);
            }
        };

        let checkpoint_manager = CheckpointManager::new(checkpoint_dir);
        
        match checkpoint_manager?.latest_checkpoint().await {
            Ok(Some(path)) => {
                tracing::info!("Found checkpoint at {}", path.display());
                Ok(Some(path))
            }
            Ok(None) => {
                tracing::info!("No checkpoint found");
                Ok(None)
            }
            Err(e) => {
                tracing::warn!("Error finding checkpoint: {}", e);
                Err(e)
            }
        }
    }

    /// Full recovery procedure with checkpoints
    pub async fn full_recovery(&self) -> Result<RecoveryResult, RollbackError> {
        tracing::info!("Starting full recovery procedure");

        // First try to restore from checkpoint
        if let Some(checkpoint_path) = self.restore_checkpoint().await? {
            tracing::info!("Restored state from checkpoint: {}", checkpoint_path.display());
        }

        // Then recover any uncommitted entries
        self.recover().await
    }

    /// Get the journal reference
    pub fn journal(&self) -> &Arc<Journal> {
        &self.journal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionId;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_recovery_no_uncommitted() {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let journal = Arc::new(Journal::new(&wal_path).unwrap());
        let manager = RecoveryManager::new(journal);

        assert!(!manager.needs_recovery().await.unwrap());

        let result = manager.recover().await.unwrap();
        assert_eq!(result.entries_recovered, 0);
        assert!(result.is_complete());
    }

    #[tokio::test]
    async fn test_recovery_with_handler() {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");

        let journal = Arc::new(Journal::new(&wal_path).unwrap());

        // Create an uncommitted entry
        let action_id = ActionId::new();
        journal
            .prepare(
                action_id,
                "test_action",
                serde_json::json!({}),
                serde_json::json!({"undo": true}),
            )
            .await
            .unwrap();

        // Create manager with handler
        let compensator = Compensator::new()
            .register_handler("test_action", super::super::compensator::handlers::noop());

        let manager = RecoveryManager::new(journal)
            .with_compensator(compensator);

        assert!(manager.needs_recovery().await.unwrap());

        let result = manager.recover().await.unwrap();
        assert_eq!(result.entries_recovered, 1);
        assert!(result.is_complete());
    }
}
