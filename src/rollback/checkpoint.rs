//! Checkpoint Manager - State snapshots for recovery
//!
//! Provides periodic snapshots of system state for faster recovery.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::journal::JournalEntryId;
use super::RollbackError;

/// A checkpoint representing system state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint ID
    pub id: u64,
    /// Timestamp when checkpoint was created
    pub created_at: DateTime<Utc>,
    /// Last journal entry ID included in this checkpoint
    pub last_entry_id: JournalEntryId,
    /// Captured state data
    pub state: HashMap<String, Vec<u8>>,
    /// Checksum for integrity
    pub checksum: String,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(id: u64, last_entry_id: JournalEntryId) -> Self {
        Self {
            id,
            created_at: Utc::now(),
            last_entry_id,
            state: HashMap::new(),
            checksum: String::new(),
        }
    }

    /// Add state data to the checkpoint
    pub fn add_state(&mut self, key: impl Into<String>, data: Vec<u8>) {
        self.state.insert(key.into(), data);
    }

    /// Finalize the checkpoint (compute checksum)
    pub fn finalize(&mut self) {
        self.checksum = self.compute_checksum();
    }

    /// Compute checksum of the checkpoint
    fn compute_checksum(&self) -> String {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(&self.id.to_le_bytes());
        hasher.update(&self.last_entry_id.as_u64().to_le_bytes());
        hasher.update(self.created_at.to_rfc3339().as_bytes());

        // Sort keys for deterministic hashing
        let mut keys: Vec<_> = self.state.keys().collect();
        keys.sort();

        for key in keys {
            hasher.update(key.as_bytes());
            if let Some(data) = self.state.get(key) {
                hasher.update(data);
            }
        }

        let hash = hasher.finalize();
        hash.to_hex().to_string()
    }

    /// Verify checkpoint integrity
    pub fn verify(&self) -> bool {
        let computed = self.compute_checksum();
        computed == self.checksum
    }
}

/// Manager for checkpoint creation and restoration
pub struct CheckpointManager {
    /// Directory for checkpoint files
    checkpoint_dir: PathBuf,
    /// Maximum number of checkpoints to keep
    max_checkpoints: usize,
    /// Current checkpoint ID counter
    next_id: u64,
}

impl CheckpointManager {
    /// Create a new checkpoint manager
    pub fn new(checkpoint_dir: impl AsRef<Path>) -> Result<Self, RollbackError> {
        let checkpoint_dir = checkpoint_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&checkpoint_dir)?;

        // Find the highest existing checkpoint ID
        let mut max_id = 0u64;
        for entry in std::fs::read_dir(&checkpoint_dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if let Some(id_str) = name.strip_prefix("checkpoint-").and_then(|s| s.strip_suffix(".json")) {
                    if let Ok(id) = id_str.parse::<u64>() {
                        max_id = max_id.max(id);
                    }
                }
            }
        }

        Ok(Self {
            checkpoint_dir,
            max_checkpoints: 5,
            next_id: max_id + 1,
        })
    }

    /// Set maximum number of checkpoints to retain
    pub fn with_max_checkpoints(mut self, max: usize) -> Self {
        self.max_checkpoints = max;
        self
    }

    /// Create a new checkpoint
    pub fn create_checkpoint(
        &mut self,
        last_entry_id: JournalEntryId,
        state_collector: impl FnOnce(&mut Checkpoint),
    ) -> Result<Checkpoint, RollbackError> {
        let id = self.next_id;
        self.next_id += 1;

        let mut checkpoint = Checkpoint::new(id, last_entry_id);
        state_collector(&mut checkpoint);
        checkpoint.finalize();

        // Save to disk
        self.save_checkpoint(&checkpoint)?;

        // Cleanup old checkpoints
        self.cleanup_old_checkpoints()?;

        info!("Created checkpoint {} at entry {}", id, last_entry_id);
        Ok(checkpoint)
    }

    /// Save a checkpoint to disk
    fn save_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), RollbackError> {
        let path = self.checkpoint_path(checkpoint.id);
        let temp_path = path.with_extension("json.tmp");

        let data = serde_json::to_vec_pretty(checkpoint)
            .map_err(|e| RollbackError::Serialization(e.to_string()))?;

        std::fs::write(&temp_path, data)?;

        // Sync and atomic rename
        let file = std::fs::File::open(&temp_path)?;
        file.sync_all()?;
        drop(file);

        std::fs::rename(&temp_path, &path)?;

        Ok(())
    }

    /// Load the latest valid checkpoint
    pub fn load_latest(&self) -> Result<Option<Checkpoint>, RollbackError> {
        let mut checkpoints = self.list_checkpoints()?;
        checkpoints.sort_by(|a, b| b.cmp(a)); // Descending order

        for id in checkpoints {
            match self.load_checkpoint(id) {
                Ok(checkpoint) => {
                    if checkpoint.verify() {
                        return Ok(Some(checkpoint));
                    } else {
                        debug!("Checkpoint {} failed verification, trying older", id);
                    }
                }
                Err(e) => {
                    debug!("Failed to load checkpoint {}: {}", id, e);
                }
            }
        }

        Ok(None)
    }

    /// Load a specific checkpoint
    pub fn load_checkpoint(&self, id: u64) -> Result<Checkpoint, RollbackError> {
        let path = self.checkpoint_path(id);
        let data = std::fs::read(&path)?;

        let checkpoint: Checkpoint = serde_json::from_slice(&data)
            .map_err(|e| RollbackError::Serialization(e.to_string()))?;

        Ok(checkpoint)
    }

    /// List all checkpoint IDs
    fn list_checkpoints(&self) -> Result<Vec<u64>, RollbackError> {
        let mut ids = Vec::new();

        for entry in std::fs::read_dir(&self.checkpoint_dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if let Some(id_str) = name.strip_prefix("checkpoint-").and_then(|s| s.strip_suffix(".json")) {
                    if let Ok(id) = id_str.parse::<u64>() {
                        ids.push(id);
                    }
                }
            }
        }

        Ok(ids)
    }

    /// Get the path for a checkpoint file
    fn checkpoint_path(&self, id: u64) -> PathBuf {
        self.checkpoint_dir.join(format!("checkpoint-{}.json", id))
    }

    /// Remove old checkpoints exceeding the limit
    fn cleanup_old_checkpoints(&self) -> Result<(), RollbackError> {
        let mut checkpoints = self.list_checkpoints()?;
        checkpoints.sort();

        while checkpoints.len() > self.max_checkpoints {
            if let Some(oldest) = checkpoints.first().copied() {
                let path = self.checkpoint_path(oldest);
                if let Err(e) = std::fs::remove_file(&path) {
                    debug!("Failed to remove old checkpoint {}: {}", oldest, e);
                } else {
                    info!("Removed old checkpoint {}", oldest);
                }
                checkpoints.remove(0);
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Get the path to the latest checkpoint file
    pub async fn latest_checkpoint(&self) -> Result<Option<PathBuf>, RollbackError> {
        let mut checkpoints = self.list_checkpoints()?;
        checkpoints.sort_by(|a, b| b.cmp(a)); // Descending order
        
        Ok(checkpoints.first().map(|id| self.checkpoint_path(*id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_verification() {
        let mut checkpoint = Checkpoint::new(1, JournalEntryId::new(100));
        checkpoint.add_state("test", b"data".to_vec());
        checkpoint.finalize();

        assert!(checkpoint.verify());

        // Tamper with data
        checkpoint.state.insert("tampered".to_string(), b"bad".to_vec());
        assert!(!checkpoint.verify());
    }
}
