//! Write-Ahead Log (Journal) - Durable action logging
//!
//! Implements a write-ahead log that ensures every action is logged
//! before execution and can be recovered after crashes.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;


use crate::actions::ActionId;

use super::RollbackError;

/// Unique identifier for a journal entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JournalEntryId(u64);

impl JournalEntryId {
    /// Create a new entry ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for JournalEntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "entry-{}", self.0)
    }
}

/// State of a journal entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JournalEntryState {
    /// Action has been prepared but not executed
    Prepared,
    /// Action executed successfully
    Committed,
    /// Action was rolled back
    RolledBack,
    /// Rollback failed - requires manual intervention
    RollbackFailed,
}

/// A journal entry representing an action (serializable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Entry ID
    pub id: JournalEntryId,
    /// Action ID
    pub action_id: ActionId,
    /// Action type
    pub action_type: String,
    /// Entry state
    pub state: JournalEntryState,
    /// Serialized action data (JSON)
    pub action_data: serde_json::Value,
    /// Serialized compensation data (JSON) - stores what's needed to reverse the action
    pub compensation_data: serde_json::Value,
    /// Timestamp when entry was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when entry was last updated
    pub updated_at: DateTime<Utc>,
    /// Checksum for integrity verification
    pub checksum: String,
}

impl JournalEntry {
    /// Create a new journal entry
    pub fn new(
        id: JournalEntryId,
        action_id: ActionId,
        action_type: impl Into<String>,
        action_data: serde_json::Value,
        compensation_data: serde_json::Value,
    ) -> Self {
        let now = Utc::now();
        let mut entry = Self {
            id,
            action_id,
            action_type: action_type.into(),
            state: JournalEntryState::Prepared,
            action_data,
            compensation_data,
            created_at: now,
            updated_at: now,
            checksum: String::new(),
        };
        entry.checksum = entry.compute_checksum();
        entry
    }

    /// Compute checksum for integrity verification
    fn compute_checksum(&self) -> String {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(&self.id.as_u64().to_le_bytes());
        hasher.update(self.action_id.to_string().as_bytes());
        hasher.update(self.action_type.as_bytes());
        hasher.update(&[self.state as u8]);
        hasher.update(self.action_data.to_string().as_bytes());
        hasher.update(self.compensation_data.to_string().as_bytes());
        hasher.update(self.created_at.to_rfc3339().as_bytes());

        let hash = hasher.finalize();
        hash.to_hex().to_string()
    }

    /// Verify the entry's integrity
    pub fn verify(&self) -> bool {
        self.checksum == self.compute_checksum()
    }

    /// Mark as committed
    pub fn commit(&mut self) {
        self.state = JournalEntryState::Committed;
        self.updated_at = Utc::now();
        self.checksum = self.compute_checksum();
    }

    /// Mark as rolled back
    pub fn rollback(&mut self) {
        self.state = JournalEntryState::RolledBack;
        self.updated_at = Utc::now();
        self.checksum = self.compute_checksum();
    }

    /// Mark as rollback failed
    pub fn rollback_failed(&mut self) {
        self.state = JournalEntryState::RollbackFailed;
        self.updated_at = Utc::now();
        self.checksum = self.compute_checksum();
    }
}

/// Uncommitted entry for recovery
#[derive(Debug)]
pub struct UncommittedEntry {
    /// Entry ID
    pub id: JournalEntryId,
    /// Action ID
    pub action_id: ActionId,
    /// Action type
    pub action_type: String,
    /// Compensation data (serialized)
    pub compensation_data: serde_json::Value,
}

/// Write-ahead log for action journaling
pub struct Journal {
    /// Path to the journal file
    path: PathBuf,
    /// In-memory entries
    entries: Arc<RwLock<HashMap<JournalEntryId, JournalEntry>>>,
    /// Next entry ID
    next_id: AtomicU64,
    /// Whether to fsync after each write
    sync_writes: bool,
}

impl Journal {
    /// Create or open a journal at the given path
    pub fn new(path: impl AsRef<Path>) -> Result<Self, RollbackError> {
        let path = path.as_ref().to_path_buf();

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let journal = Self {
            path,
            entries: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            sync_writes: true,
        };

        // Load existing entries
        journal.load()?;

        Ok(journal)
    }

    /// Create with custom settings
    pub fn with_sync(path: impl AsRef<Path>, sync_writes: bool) -> Result<Self, RollbackError> {
        let mut journal = Self::new(path)?;
        journal.sync_writes = sync_writes;
        Ok(journal)
    }

    /// Load entries from disk
    fn load(&self) -> Result<(), RollbackError> {
        if !self.path.exists() {
            tracing::info!("No existing journal at {}", self.path.display());
            return Ok(());
        }

        let file = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(file);

        let mut entries = HashMap::new();
        let mut max_id = 0u64;
        let mut line_num = 0;

        for line in reader.lines() {
            line_num += 1;
            let line = line?;
            if line.is_empty() {
                continue;
            }

            match serde_json::from_str::<JournalEntry>(&line) {
                Ok(entry) => {
                    if !entry.verify() {
                        tracing::warn!(
                            "Journal entry {} failed integrity check at line {}",
                            entry.id, line_num
                        );
                        continue;
                    }

                    max_id = max_id.max(entry.id.as_u64());
                    entries.insert(entry.id, entry);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse journal entry at line {}: {}", line_num, e);
                }
            }
        }

        // Update next ID
        self.next_id.store(max_id + 1, Ordering::SeqCst);

        // Update in-memory entries
        let entries_clone = entries.clone();
        *self.entries.write().unwrap() = entries;

        tracing::info!("Loaded {} journal entries", entries_clone.len());
        Ok(())
    }

    /// Prepare an action (log before execution)
    pub async fn prepare(
        &self,
        action_id: ActionId,
        action_type: impl Into<String>,
        action_data: serde_json::Value,
        compensation_data: serde_json::Value,
    ) -> Result<JournalEntryId, RollbackError> {
        let entry_id = JournalEntryId::new(self.next_id.fetch_add(1, Ordering::SeqCst));

        let entry = JournalEntry::new(
            entry_id,
            action_id,
            action_type,
            action_data,
            compensation_data,
        );

        // Write to disk first (WAL semantics)
        self.append_entry(&entry).await?;

        // Then add to memory
        self.entries.write().unwrap().insert(entry_id, entry);

        tracing::debug!("Prepared journal entry {}", entry_id);
        Ok(entry_id)
    }

    /// Commit an action (mark as successful)
    pub async fn commit(&self, entry_id: JournalEntryId) -> Result<(), RollbackError> {
        let mut entries = self.entries.write().unwrap();

        let entry = entries
            .get_mut(&entry_id)
            .ok_or_else(|| RollbackError::EntryNotFound(entry_id.to_string()))?;

        entry.commit();

        // Write update to disk
        self.append_entry(entry).await?;

        tracing::debug!("Committed journal entry {}", entry_id);
        Ok(())
    }

    /// Mark an action as rolled back
    pub async fn mark_rolled_back(&self, entry_id: JournalEntryId) -> Result<(), RollbackError> {
        let mut entries = self.entries.write().unwrap();

        let entry = entries
            .get_mut(&entry_id)
            .ok_or_else(|| RollbackError::EntryNotFound(entry_id.to_string()))?;

        entry.rollback();

        self.append_entry(entry).await?;

        tracing::debug!("Marked journal entry {} as rolled back", entry_id);
        Ok(())
    }

    /// Mark a rollback as failed
    pub async fn mark_rollback_failed(&self, entry_id: JournalEntryId) -> Result<(), RollbackError> {
        let mut entries = self.entries.write().unwrap();

        let entry = entries
            .get_mut(&entry_id)
            .ok_or_else(|| RollbackError::EntryNotFound(entry_id.to_string()))?;

        entry.rollback_failed();

        self.append_entry(entry).await?;

        tracing::warn!("Marked journal entry {} as rollback failed", entry_id);
        Ok(())
    }

    /// Append an entry to the journal file
    async fn append_entry(&self, entry: &JournalEntry) -> Result<(), RollbackError> {
        let line = serde_json::to_string(entry)
            .map_err(|e| RollbackError::Serialization(e.to_string()))?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        writeln!(file, "{}", line)?;

        if self.sync_writes {
            file.sync_all()?;
        }

        Ok(())
    }

    /// Get uncommitted entries for recovery
    pub async fn get_uncommitted(&self) -> Vec<UncommittedEntry> {
        let entries = self.entries.read().unwrap();

        entries
            .values()
            .filter(|e| e.state == JournalEntryState::Prepared)
            .map(|e| UncommittedEntry {
                id: e.id,
                action_id: e.action_id.clone(),
                action_type: e.action_type.clone(),
                compensation_data: e.compensation_data.clone(),
            })
            .collect()
    }

    /// Get an entry by ID
    pub async fn get(&self, entry_id: JournalEntryId) -> Option<JournalEntry> {
        self.entries.read().unwrap().get(&entry_id).cloned()
    }

    /// Get all entries
    pub async fn get_all(&self) -> Vec<JournalEntry> {
        self.entries.read().unwrap().values().cloned().collect()
    }

    /// Get entries in a specific state
    pub async fn get_by_state(&self, state: JournalEntryState) -> Vec<JournalEntry> {
        self.entries
            .read().unwrap()
            .values()
            .filter(|e| e.state == state)
            .cloned()
            .collect()
    }

    /// Compact the journal (remove old committed entries)
    pub async fn compact(&self, keep_last: usize) -> Result<usize, RollbackError> {
        let mut entries = self.entries.write().unwrap();

        // Collect entries to remove (old committed/rolled back)
        let mut to_remove: Vec<JournalEntryId> = entries
            .values()
            .filter(|e| {
                e.state == JournalEntryState::Committed
                    || e.state == JournalEntryState::RolledBack
            })
            .map(|e| (e.id, e.updated_at))
            .collect::<Vec<_>>()
            .into_iter()
            .sorted_by_key(|(_, ts)| *ts)
            .map(|(id, _)| id)
            .collect();

        // Keep the most recent
        if to_remove.len() > keep_last {
            to_remove.truncate(to_remove.len() - keep_last);
        } else {
            to_remove.clear();
        }

        let removed_count = to_remove.len();

        for id in &to_remove {
            entries.remove(id);
        }

        // Rewrite journal file
        if removed_count > 0 {
            self.rewrite_journal(&entries).await?;
        }

        tracing::info!("Compacted journal, removed {} entries", removed_count);
        Ok(removed_count)
    }

    /// Rewrite the journal file with current entries
    async fn rewrite_journal(
        &self,
        entries: &HashMap<JournalEntryId, JournalEntry>,
    ) -> Result<(), RollbackError> {
        let temp_path = self.path.with_extension("tmp");

        let mut file = std::fs::File::create(&temp_path)?;

        for entry in entries.values() {
            let line = serde_json::to_string(entry)
                .map_err(|e| RollbackError::Serialization(e.to_string()))?;
            writeln!(file, "{}", line)?;
        }

        file.sync_all()?;

        // Atomic rename
        std::fs::rename(&temp_path, &self.path)?;

        Ok(())
    }

    /// Flush the journal
    pub async fn flush(&self) -> Result<(), RollbackError> {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)?;
        file.sync_all()?;
        Ok(())
    }

    /// Clear the journal (for testing)
    #[cfg(test)]
    pub async fn clear(&self) -> Result<(), RollbackError> {
        self.entries.write().unwrap().clear();
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

// Helper trait for sorting
trait Sorted: Iterator {
    fn sorted_by_key<K, F>(self, f: F) -> std::vec::IntoIter<Self::Item>
    where
        Self: Sized,
        F: FnMut(&Self::Item) -> K,
        K: Ord,
    {
        let mut v: Vec<_> = self.collect();
        v.sort_by_key(f);
        v.into_iter()
    }
}

impl<I: Iterator> Sorted for I {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_journal_basic_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wal");

        let journal = Journal::new(&path).unwrap();

        let action_id = ActionId::new();
        let entry_id = journal
            .prepare(
                action_id.clone(),
                "test_action",
                serde_json::json!({"target": "test"}),
                serde_json::json!({"undo": true}),
            )
            .await
            .unwrap();

        // Should be uncommitted
        let uncommitted = journal.get_uncommitted().await;
        assert_eq!(uncommitted.len(), 1);

        // Commit
        journal.commit(entry_id).await.unwrap();

        // Should be empty now
        let uncommitted = journal.get_uncommitted().await;
        assert_eq!(uncommitted.len(), 0);
    }

    #[tokio::test]
    async fn test_journal_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wal");

        let action_id = ActionId::new();

        // Create and prepare
        {
            let journal = Journal::new(&path).unwrap();
            journal
                .prepare(
                    action_id.clone(),
                    "test_action",
                    serde_json::json!({"target": "test"}),
                    serde_json::json!({"undo": true}),
                )
                .await
                .unwrap();
        }

        // Reload and verify
        {
            let journal = Journal::new(&path).unwrap();
            let uncommitted = journal.get_uncommitted().await;
            assert_eq!(uncommitted.len(), 1);
        }
    }
}
