//! TTL Engine - Automatic expiration of temporary firewall rules
//!
//! This module manages time-to-live (TTL) for temporary firewall rules.
//! Key properties:
//!
//! - **No busy loops**: Uses a single timer for the next expiration
//! - **Crash resilient**: Expiration times persisted to disk
//! - **Safe removal**: Uses the same firewall backend as normal operations
//! - **Rollback safe**: Coordinates with rollback engine to prevent races
//!
//! See `docs/TTL_ENGINE.md` for detailed design.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Notify;
use tokio::time::Instant;
use tracing::instrument;

use crate::firewall::{FirewallBackend, FirewallError, RuleId};

// ============================================================================
// Error Types
// ============================================================================

/// Errors from TTL operations
#[derive(Error, Debug)]
pub enum TtlError {
    /// Invalid TTL duration
    #[error("Invalid TTL: {0}")]
    InvalidTtl(String),

    /// Rule not found in TTL registry
    #[error("Rule not found in TTL registry: {0}")]
    RuleNotFound(String),

    /// Rule already has TTL
    #[error("Rule already has TTL: {0}")]
    AlreadyRegistered(String),

    /// IO error during persistence
    #[error("Persistence error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Coordination error with rollback
    #[error("Coordination error: {0}")]
    CoordinationError(String),

    /// Firewall backend error
    #[error("Firewall error: {0}")]
    FirewallError(#[from] FirewallError),

    /// Engine shutdown
    #[error("TTL engine is shut down")]
    Shutdown,
}

/// Result type for TTL operations
pub type TtlResult<T> = Result<T, TtlError>;

// ============================================================================
// TTL Entry
// ============================================================================

/// State of a TTL entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlState {
    /// Rule is active, waiting for expiration
    Active,
    /// Expiration in progress
    Expiring,
    /// Successfully expired and removed
    Expired,
    /// Cancelled before expiration (manual removal or rollback)
    Cancelled,
    /// Expiration failed, needs retry
    Failed,
}

/// A rule with time-to-live metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlEntry {
    /// The firewall rule ID
    pub rule_id: RuleId,

    /// Absolute expiration time (Unix timestamp milliseconds)
    pub expires_at_ms: u64,

    /// When the rule was created (Unix timestamp milliseconds)
    pub created_at_ms: u64,

    /// Original TTL duration in seconds
    pub original_ttl_secs: u64,

    /// Current state
    pub state: TtlState,

    /// Generation counter for CAS operations
    pub generation: u64,
}

impl TtlEntry {
    /// Create a new TTL entry
    pub fn new(rule_id: RuleId, ttl: Duration) -> Self {
        let now_ms = current_time_ms();
        let ttl_secs = ttl.as_secs();

        Self {
            rule_id,
            expires_at_ms: now_ms + (ttl_secs * 1000),
            created_at_ms: now_ms,
            original_ttl_secs: ttl_secs,
            state: TtlState::Active,
            generation: 1,
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        current_time_ms() >= self.expires_at_ms
    }

    /// Get remaining time until expiration
    pub fn remaining(&self) -> Option<Duration> {
        let now = current_time_ms();
        if now >= self.expires_at_ms {
            None
        } else {
            Some(Duration::from_millis(self.expires_at_ms - now))
        }
    }

    /// Extend the TTL by the given duration
    pub fn extend(&mut self, additional: Duration) {
        self.expires_at_ms += additional.as_millis() as u64;
        self.generation += 1;
    }

    /// Transition to a new state
    fn transition(&mut self, new_state: TtlState) {
        self.state = new_state;
        self.generation += 1;
    }
}

// ============================================================================
// TTL Registry (In-Memory)
// ============================================================================

/// In-memory registry of all TTL entries
pub struct TtlRegistry {
    /// Primary index: rule_id → entry
    by_rule_id: HashMap<RuleId, TtlEntry>,

    /// Time-ordered index: expires_at_ms → set of rule IDs
    by_expiration: BTreeMap<u64, HashSet<RuleId>>,

    /// Version counter for change detection
    version: AtomicU64,
}

impl TtlRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            by_rule_id: HashMap::new(),
            by_expiration: BTreeMap::new(),
            version: AtomicU64::new(0),
        }
    }

    /// Get the soonest expiration time
    pub fn next_expiration(&self) -> Option<u64> {
        self.by_expiration.keys().next().copied()
    }

    /// Get all entries expiring at or before the given time
    pub fn entries_expiring_before(&self, deadline_ms: u64) -> Vec<TtlEntry> {
        let mut result = Vec::new();

        for (&_exp_time, rule_ids) in self.by_expiration.range(..=deadline_ms) {
            for rule_id in rule_ids {
                if let Some(entry) = self.by_rule_id.get(rule_id) {
                    if entry.state == TtlState::Active || entry.state == TtlState::Failed {
                        result.push(entry.clone());
                    }
                }
            }
        }

        result
    }

    /// Register a new TTL entry
    pub fn register(&mut self, entry: TtlEntry) -> TtlResult<()> {
        if self.by_rule_id.contains_key(&entry.rule_id) {
            return Err(TtlError::AlreadyRegistered(entry.rule_id.to_string()));
        }

        let rule_id = entry.rule_id.clone();
        let expires_at = entry.expires_at_ms;

        self.by_rule_id.insert(rule_id.clone(), entry);
        self.by_expiration
            .entry(expires_at)
            .or_default()
            .insert(rule_id);

        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Cancel a TTL entry
    pub fn cancel(&mut self, rule_id: &RuleId) -> Option<TtlEntry> {
        if let Some(mut entry) = self.by_rule_id.remove(rule_id) {
            // Remove from expiration index
            if let Some(set) = self.by_expiration.get_mut(&entry.expires_at_ms) {
                set.remove(rule_id);
                if set.is_empty() {
                    self.by_expiration.remove(&entry.expires_at_ms);
                }
            }

            entry.transition(TtlState::Cancelled);
            self.version.fetch_add(1, Ordering::SeqCst);
            Some(entry)
        } else {
            None
        }
    }

    /// Get an entry by rule ID
    pub fn get(&self, rule_id: &RuleId) -> Option<&TtlEntry> {
        self.by_rule_id.get(rule_id)
    }

    /// Get a mutable entry by rule ID
    pub fn get_mut(&mut self, rule_id: &RuleId) -> Option<&mut TtlEntry> {
        self.by_rule_id.get_mut(rule_id)
    }

    /// Mark an entry as expiring
    pub fn mark_expiring(&mut self, rule_id: &RuleId) -> TtlResult<()> {
        let entry = self
            .by_rule_id
            .get_mut(rule_id)
            .ok_or_else(|| TtlError::RuleNotFound(rule_id.to_string()))?;

        entry.transition(TtlState::Expiring);
        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Mark an entry as expired and remove it
    pub fn mark_expired(&mut self, rule_id: &RuleId) -> TtlResult<TtlEntry> {
        let mut entry = self
            .by_rule_id
            .remove(rule_id)
            .ok_or_else(|| TtlError::RuleNotFound(rule_id.to_string()))?;

        // Remove from expiration index
        if let Some(set) = self.by_expiration.get_mut(&entry.expires_at_ms) {
            set.remove(rule_id);
            if set.is_empty() {
                self.by_expiration.remove(&entry.expires_at_ms);
            }
        }

        entry.transition(TtlState::Expired);
        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(entry)
    }

    /// Mark an entry as failed
    pub fn mark_failed(&mut self, rule_id: &RuleId) -> TtlResult<()> {
        let entry = self
            .by_rule_id
            .get_mut(rule_id)
            .ok_or_else(|| TtlError::RuleNotFound(rule_id.to_string()))?;

        entry.transition(TtlState::Failed);
        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// List all active entries
    pub fn list_active(&self) -> Vec<TtlEntry> {
        self.by_rule_id
            .values()
            .filter(|e| e.state == TtlState::Active)
            .cloned()
            .collect()
    }

    /// Get count of active entries
    pub fn active_count(&self) -> usize {
        self.by_rule_id
            .values()
            .filter(|e| e.state == TtlState::Active)
            .count()
    }

    /// Update expiration time for an entry (for extend)
    pub fn update_expiration(&mut self, rule_id: &RuleId, new_expires_at: u64) -> TtlResult<()> {
        let entry = self
            .by_rule_id
            .get_mut(rule_id)
            .ok_or_else(|| TtlError::RuleNotFound(rule_id.to_string()))?;

        let old_expires = entry.expires_at_ms;
        entry.expires_at_ms = new_expires_at;
        entry.generation += 1;

        // Update expiration index
        if let Some(set) = self.by_expiration.get_mut(&old_expires) {
            set.remove(rule_id);
            if set.is_empty() {
                self.by_expiration.remove(&old_expires);
            }
        }

        self.by_expiration
            .entry(new_expires_at)
            .or_default()
            .insert(rule_id.clone());

        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl Default for TtlRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TTL Persister
// ============================================================================

/// Persistent log entry operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TtlLogOp {
    /// Register a new TTL
    Register(TtlEntry),
    /// Update entry state
    Update {
        rule_id: RuleId,
        state: TtlState,
        generation: u64,
    },
    /// Remove entry (tombstone)
    Remove { rule_id: RuleId },
    /// Compaction marker
    Compacted { up_to_seq: u64 },
}

/// A single log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TtlLogEntry {
    /// Monotonic sequence number
    seq: u64,
    /// Timestamp of this log entry
    timestamp_ms: u64,
    /// The operation
    op: TtlLogOp,
}

/// Persistent storage for TTL state
pub struct TtlPersister {
    /// Path to the TTL state file
    path: PathBuf,
    /// Next sequence number
    next_seq: AtomicU64,
    /// Whether to fsync after each write
    sync_writes: bool,
}

impl TtlPersister {
    /// Create or open a persister at the given path
    pub fn new(path: impl AsRef<Path>) -> TtlResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Determine next sequence number from existing file
        let next_seq = if path.exists() {
            Self::find_max_seq(&path)? + 1
        } else {
            1
        };

        Ok(Self {
            path,
            next_seq: AtomicU64::new(next_seq),
            sync_writes: true,
        })
    }

    /// Create with custom sync setting
    pub fn with_sync(path: impl AsRef<Path>, sync_writes: bool) -> TtlResult<Self> {
        let mut persister = Self::new(path)?;
        persister.sync_writes = sync_writes;
        Ok(persister)
    }

    /// Find the maximum sequence number in the log
    fn find_max_seq(path: &Path) -> TtlResult<u64> {
        use std::io::{BufRead, BufReader};

        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut max_seq = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<TtlLogEntry>(&line) {
                max_seq = max_seq.max(entry.seq);
            }
        }

        Ok(max_seq)
    }

    /// Load all TTL entries from disk
    pub fn load(&self) -> TtlResult<Vec<TtlEntry>> {
        use std::io::{BufRead, BufReader};

        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(file);

        // Replay log to reconstruct state
        let mut entries: HashMap<RuleId, TtlEntry> = HashMap::new();
        let mut compacted_up_to = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let log_entry: TtlLogEntry = serde_json::from_str(&line)
                .map_err(|e| TtlError::SerializationError(e.to_string()))?;

            // Skip entries before compaction marker
            if log_entry.seq <= compacted_up_to {
                continue;
            }

            match log_entry.op {
                TtlLogOp::Register(entry) => {
                    entries.insert(entry.rule_id.clone(), entry);
                }
                TtlLogOp::Update {
                    rule_id,
                    state,
                    generation,
                } => {
                    if let Some(entry) = entries.get_mut(&rule_id) {
                        if generation > entry.generation {
                            entry.state = state;
                            entry.generation = generation;
                        }
                    }
                }
                TtlLogOp::Remove { rule_id } => {
                    entries.remove(&rule_id);
                }
                TtlLogOp::Compacted { up_to_seq } => {
                    compacted_up_to = up_to_seq;
                }
            }
        }

        Ok(entries.into_values().collect())
    }

    /// Persist a new or updated entry
    pub fn persist(&self, entry: &TtlEntry) -> TtlResult<()> {
        self.write_op(TtlLogOp::Register(entry.clone()))
    }

    /// Persist a state update
    pub fn persist_update(&self, rule_id: &RuleId, state: TtlState, generation: u64) -> TtlResult<()> {
        self.write_op(TtlLogOp::Update {
            rule_id: rule_id.clone(),
            state,
            generation,
        })
    }

    /// Write a remove tombstone
    pub fn remove(&self, rule_id: &RuleId) -> TtlResult<()> {
        self.write_op(TtlLogOp::Remove {
            rule_id: rule_id.clone(),
        })
    }

    /// Write a log operation
    fn write_op(&self, op: TtlLogOp) -> TtlResult<()> {
        use std::io::Write;

        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let log_entry = TtlLogEntry {
            seq,
            timestamp_ms: current_time_ms(),
            op,
        };

        let mut line =
            serde_json::to_string(&log_entry).map_err(|e| TtlError::SerializationError(e.to_string()))?;
        line.push('\n');

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        file.write_all(line.as_bytes())?;

        if self.sync_writes {
            file.sync_all()?;
        }

        Ok(())
    }

    /// Compact the log file
    pub fn compact(&self, live_entries: &[TtlEntry]) -> TtlResult<()> {
        use std::io::Write;

        let temp_path = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&temp_path)?;

        // Write compaction marker
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let marker = TtlLogEntry {
            seq,
            timestamp_ms: current_time_ms(),
            op: TtlLogOp::Compacted { up_to_seq: seq - 1 },
        };
        let line = serde_json::to_string(&marker).map_err(|e| TtlError::SerializationError(e.to_string()))?;
        writeln!(file, "{}", line)?;

        // Write all live entries
        for entry in live_entries {
            let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
            let log_entry = TtlLogEntry {
                seq,
                timestamp_ms: current_time_ms(),
                op: TtlLogOp::Register(entry.clone()),
            };
            let line =
                serde_json::to_string(&log_entry).map_err(|e| TtlError::SerializationError(e.to_string()))?;
            writeln!(file, "{}", line)?;
        }

        file.sync_all()?;
        drop(file);

        // Atomic rename
        std::fs::rename(&temp_path, &self.path)?;

        Ok(())
    }
}

// ============================================================================
// TTL-Rollback Coordinator
// ============================================================================

/// State of a rule removal operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleRemovalState {
    /// Rule exists and can be removed
    Active,
    /// TTL is processing removal
    TtlRemoving,
    /// Rollback is processing removal
    RollbackRemoving,
    /// Rule has been removed (terminal)
    Removed,
}

/// Coordinator for TTL and rollback operations
///
/// Prevents race conditions where TTL expiration and rollback
/// try to remove the same rule simultaneously.
pub struct TtlRollbackCoordinator {
    /// Per-rule removal states
    removal_states: RwLock<HashMap<RuleId, RuleRemovalState>>,

    /// Flag indicating rollback is in progress
    rollback_in_progress: std::sync::atomic::AtomicBool,

    /// Notifier for rollback completion
    rollback_complete: Notify,
}

impl TtlRollbackCoordinator {
    /// Create a new coordinator
    pub fn new() -> Self {
        Self {
            removal_states: RwLock::new(HashMap::new()),
            rollback_in_progress: std::sync::atomic::AtomicBool::new(false),
            rollback_complete: Notify::new(),
        }
    }

    /// Check if rollback is in progress
    pub fn is_rollback_in_progress(&self) -> bool {
        self.rollback_in_progress.load(Ordering::SeqCst)
    }

    /// Wait for any in-progress rollback to complete
    pub async fn wait_for_rollback(&self) {
        while self.rollback_in_progress.load(Ordering::SeqCst) {
            self.rollback_complete.notified().await;
        }
    }

    /// Called by TTL engine before removing an expired rule
    pub fn try_acquire_ttl_removal(&self, rule_id: &RuleId) -> Result<(), CoordinationError> {
        // If rollback is in progress, defer
        if self.rollback_in_progress.load(Ordering::SeqCst) {
            return Err(CoordinationError::RollbackInProgress);
        }

        let mut states = self.removal_states.write().unwrap();
        let state = states.entry(rule_id.clone()).or_insert(RuleRemovalState::Active);

        match *state {
            RuleRemovalState::Active => {
                *state = RuleRemovalState::TtlRemoving;
                Ok(())
            }
            RuleRemovalState::RollbackRemoving => Err(CoordinationError::RollbackInProgress),
            RuleRemovalState::TtlRemoving => Err(CoordinationError::AlreadyRemoving),
            RuleRemovalState::Removed => Err(CoordinationError::AlreadyRemoved),
        }
    }

    /// Called by rollback engine before removing a rule
    pub fn try_acquire_rollback_removal(&self, rule_id: &RuleId) -> Result<(), CoordinationError> {
        let mut states = self.removal_states.write().unwrap();
        let state = states.entry(rule_id.clone()).or_insert(RuleRemovalState::Active);

        match *state {
            RuleRemovalState::Active => {
                *state = RuleRemovalState::RollbackRemoving;
                Ok(())
            }
            RuleRemovalState::TtlRemoving => Err(CoordinationError::TtlInProgress),
            RuleRemovalState::RollbackRemoving => Err(CoordinationError::AlreadyRemoving),
            RuleRemovalState::Removed => Err(CoordinationError::AlreadyRemoved),
        }
    }

    /// Mark a removal as complete
    pub fn complete_removal(&self, rule_id: &RuleId) {
        let mut states = self.removal_states.write().unwrap();
        states.insert(rule_id.clone(), RuleRemovalState::Removed);
    }

    /// Release a removal lock without completing (for errors)
    pub fn release_removal(&self, rule_id: &RuleId) {
        let mut states = self.removal_states.write().unwrap();
        if let Some(state) = states.get_mut(rule_id) {
            if *state == RuleRemovalState::TtlRemoving || *state == RuleRemovalState::RollbackRemoving {
                *state = RuleRemovalState::Active;
            }
        }
    }

    /// Begin a rollback operation
    pub fn begin_rollback(&self) {
        self.rollback_in_progress.store(true, Ordering::SeqCst);
    }

    /// End a rollback operation
    pub fn end_rollback(&self) {
        self.rollback_in_progress.store(false, Ordering::SeqCst);
        self.rollback_complete.notify_waiters();
    }

    /// Cleanup old removal states (periodic maintenance)
    pub fn cleanup_old_states(&self, max_entries: usize) {
        let mut states = self.removal_states.write().unwrap();
        if states.len() > max_entries {
            // Remove all "Removed" entries
            states.retain(|_, state| *state != RuleRemovalState::Removed);
        }
    }
}

impl Default for TtlRollbackCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Coordination errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinationError {
    /// Rollback is currently in progress
    RollbackInProgress,
    /// TTL is currently processing this rule
    TtlInProgress,
    /// Another operation is already removing this rule
    AlreadyRemoving,
    /// Rule has already been removed
    AlreadyRemoved,
}

impl std::fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RollbackInProgress => write!(f, "rollback in progress"),
            Self::TtlInProgress => write!(f, "TTL expiration in progress"),
            Self::AlreadyRemoving => write!(f, "already being removed"),
            Self::AlreadyRemoved => write!(f, "already removed"),
        }
    }
}

// ============================================================================
// Timer Tick
// ============================================================================

/// Timer notification
#[derive(Debug, Clone)]
pub struct TtlTick {
    /// The scheduled wakeup time that triggered this tick
    pub scheduled_at_ms: u64,
    /// Actual time when tick occurred
    pub actual_at_ms: u64,
}

// ============================================================================
// TTL Engine Configuration
// ============================================================================

/// Configuration for the TTL engine
#[derive(Debug, Clone)]
pub struct TtlConfig {
    /// Path to TTL state file
    pub state_path: PathBuf,
    /// Whether to fsync after each write
    pub sync_writes: bool,
    /// Maximum allowed TTL (default: 30 days)
    pub max_ttl: Duration,
    /// Minimum allowed TTL (default: 1 second)
    pub min_ttl: Duration,
    /// Log file size threshold for compaction (bytes)
    pub compaction_threshold_bytes: u64,
}

impl Default for TtlConfig {
    fn default() -> Self {
        Self {
            state_path: PathBuf::from("/var/lib/whitequbit/ttl.log"),
            sync_writes: true,
            max_ttl: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            min_ttl: Duration::from_secs(1),
            compaction_threshold_bytes: 10 * 1024 * 1024, // 10 MB
        }
    }
}

// ============================================================================
// Recovery Statistics
// ============================================================================

/// Statistics from TTL recovery
#[derive(Debug, Default)]
pub struct RecoveryStats {
    /// Entries loaded from disk
    pub loaded: usize,
    /// Entries that expired during downtime
    pub expired_during_downtime: usize,
    /// Entries with failed state that need retry
    pub pending_retry: usize,
    /// Stale entries cleaned up
    pub cleaned_up: usize,
}

// ============================================================================
// TTL Engine
// ============================================================================

/// The TTL Engine manages automatic expiration of temporary firewall rules
pub struct TtlEngine<B: FirewallBackend> {
    /// In-memory registry
    registry: Arc<RwLock<TtlRegistry>>,
    /// Persistent storage
    persister: TtlPersister,
    /// Coordination with rollback
    coordinator: Arc<TtlRollbackCoordinator>,
    /// Firewall backend
    firewall: Arc<B>,
    /// Configuration
    config: TtlConfig,
    /// Next scheduled wakeup time (ms)
    next_wakeup_ms: AtomicU64,
    /// Shutdown flag
    shutdown: std::sync::atomic::AtomicBool,
}

impl<B: FirewallBackend> TtlEngine<B> {
    /// Create a new TTL engine
    pub fn new(
        config: TtlConfig,
        firewall: Arc<B>,
        coordinator: Arc<TtlRollbackCoordinator>,
    ) -> TtlResult<Self> {
        let persister = TtlPersister::with_sync(&config.state_path, config.sync_writes)?;

        Ok(Self {
            registry: Arc::new(RwLock::new(TtlRegistry::new())),
            persister,
            coordinator,
            firewall,
            config,
            next_wakeup_ms: AtomicU64::new(0),
            shutdown: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Recover state from disk after restart
    #[instrument(skip(self))]
    pub async fn recover(&self) -> TtlResult<RecoveryStats> {
        tracing::info!("Recovering TTL state from disk");
        let mut stats = RecoveryStats::default();

        let entries = self.persister.load()?;
        stats.loaded = entries.len();

        let now_ms = current_time_ms();
        let mut expired_rules = Vec::new();
        let mut failed_rules = Vec::new();

        for entry in entries {
            match entry.state {
                TtlState::Active => {
                    if entry.expires_at_ms <= now_ms {
                        // Expired during downtime
                        expired_rules.push(entry);
                        stats.expired_during_downtime += 1;
                    } else {
                        // Still valid, add to registry
                        let mut registry = self.registry.write().unwrap();
                        let _ = registry.register(entry);
                    }
                }
                TtlState::Expiring | TtlState::Failed => {
                    // Interrupted during expiration, needs retry
                    failed_rules.push(entry);
                    stats.pending_retry += 1;
                }
                TtlState::Expired | TtlState::Cancelled => {
                    // Stale, cleanup
                    self.persister.remove(&entry.rule_id)?;
                    stats.cleaned_up += 1;
                }
            }
        }

        tracing::info!(?stats, "TTL recovery complete");

        // Process expired and failed rules
        for entry in expired_rules.into_iter().chain(failed_rules.into_iter()) {
            if let Err(e) = self.process_single_expiration(&entry).await {
                tracing::warn!(rule_id = %entry.rule_id, error = %e, "Failed to process expired rule during recovery");
            }
        }

        // Schedule next wakeup
        self.reschedule_timer();

        Ok(stats)
    }

    /// Register a rule with TTL
    #[instrument(skip(self), fields(%rule_id))]
    pub fn register(&self, rule_id: RuleId, ttl: Duration) -> TtlResult<()> {
        // Validate TTL
        if ttl < self.config.min_ttl {
            return Err(TtlError::InvalidTtl(format!(
                "TTL {} is below minimum {:?}",
                ttl.as_secs(),
                self.config.min_ttl
            )));
        }
        if ttl > self.config.max_ttl {
            return Err(TtlError::InvalidTtl(format!(
                "TTL {:?} exceeds maximum {:?}",
                ttl,
                self.config.max_ttl
            )));
        }

        let entry = TtlEntry::new(rule_id.clone(), ttl);

        // Persist first (crash safety)
        self.persister.persist(&entry)?;

        // Add to registry
        {
            let mut registry = self.registry.write().unwrap();
            registry.register(entry)?;
        }

        // Reschedule timer if this is the soonest expiration
        self.reschedule_timer();

        tracing::info!(%rule_id, ttl_secs = ttl.as_secs(), "Registered TTL");
        Ok(())
    }

    /// Cancel TTL (rule removed manually or by rollback)
    pub fn cancel(&self, rule_id: &RuleId) {
        let cancelled = {
            let mut registry = self.registry.write().unwrap();
            registry.cancel(rule_id)
        };

        if let Some(_entry) = cancelled {
            // Persist cancellation
            let _ = self.persister.remove(rule_id);
            tracing::debug!(%rule_id, "Cancelled TTL");
        }
    }

    /// Extend TTL for an existing rule
    pub fn extend(&self, rule_id: &RuleId, additional: Duration) -> TtlResult<()> {
        let _new_expires = {
            let mut registry = self.registry.write().unwrap();
            let entry = registry
                .get_mut(rule_id)
                .ok_or_else(|| TtlError::RuleNotFound(rule_id.to_string()))?;

            // Check if new TTL would exceed max
            let new_ttl_secs = entry.original_ttl_secs + additional.as_secs();
            if Duration::from_secs(new_ttl_secs) > self.config.max_ttl {
                return Err(TtlError::InvalidTtl(format!(
                    "Extended TTL would exceed maximum {:?}",
                    self.config.max_ttl
                )));
            }

            entry.extend(additional);
            let new_expires = entry.expires_at_ms;

            // Update expiration index
            registry.update_expiration(rule_id, new_expires)?;
            new_expires
        };

        // Persist update
        let registry = self.registry.read().unwrap();
        if let Some(entry) = registry.get(rule_id) {
            self.persister.persist(entry)?;
        }

        // Reschedule timer
        self.reschedule_timer();

        tracing::info!(%rule_id, additional_secs = additional.as_secs(), "Extended TTL");
        Ok(())
    }

    /// Get remaining TTL for a rule
    pub fn remaining(&self, rule_id: &RuleId) -> Option<Duration> {
        let registry = self.registry.read().unwrap();
        registry.get(rule_id).and_then(|e| e.remaining())
    }

    /// List all active TTL entries
    pub fn list_active(&self) -> Vec<TtlEntry> {
        let registry = self.registry.read().unwrap();
        registry.list_active()
    }

    /// Get the next tick time (for integration with event loop)
    pub fn next_tick_deadline(&self) -> Option<Instant> {
        let registry = self.registry.read().unwrap();
        registry.next_expiration().map(|exp_ms| {
            let now_ms = current_time_ms();
            if exp_ms <= now_ms {
                Instant::now()
            } else {
                Instant::now() + Duration::from_millis(exp_ms - now_ms)
            }
        })
    }

    /// Process expired rules
    #[instrument(skip(self))]
    pub async fn process_expirations(&self) -> TtlResult<usize> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(TtlError::Shutdown);
        }

        // Wait for any rollback to complete
        self.coordinator.wait_for_rollback().await;

        let now_ms = current_time_ms();
        let expired: Vec<TtlEntry> = {
            let registry = self.registry.read().unwrap();
            registry.entries_expiring_before(now_ms)
        };

        if expired.is_empty() {
            self.reschedule_timer();
            return Ok(0);
        }

        tracing::info!(count = expired.len(), "Processing expired TTL rules");
        let mut processed = 0;

        for entry in expired {
            match self.process_single_expiration(&entry).await {
                Ok(()) => processed += 1,
                Err(e) => {
                    tracing::warn!(rule_id = %entry.rule_id, error = %e, "Failed to expire rule");
                }
            }
        }

        self.reschedule_timer();
        Ok(processed)
    }

    /// Process a single expiration
    async fn process_single_expiration(&self, entry: &TtlEntry) -> TtlResult<()> {
        let rule_id = &entry.rule_id;

        // Try to acquire coordination lock
        match self.coordinator.try_acquire_ttl_removal(rule_id) {
            Ok(()) => {}
            Err(CoordinationError::RollbackInProgress) => {
                tracing::debug!(%rule_id, "Deferring expiration due to rollback");
                return Ok(()); // Will retry on next tick
            }
            Err(CoordinationError::AlreadyRemoved) => {
                // Rule already removed, just cleanup our state
                let mut registry = self.registry.write().unwrap();
                let _ = registry.mark_expired(rule_id);
                self.persister.remove(rule_id)?;
                return Ok(());
            }
            Err(e) => {
                return Err(TtlError::CoordinationError(e.to_string()));
            }
        }

        // Mark as expiring
        {
            let mut registry = self.registry.write().unwrap();
            registry.mark_expiring(rule_id)?;
        }
        self.persister.persist_update(rule_id, TtlState::Expiring, entry.generation + 1)?;

        // Remove through firewall backend
        let result = self.firewall.remove_rule(rule_id).await;

        match result {
            Ok(_) => {
                // Success - mark as expired
                let mut registry = self.registry.write().unwrap();
                let _ = registry.mark_expired(rule_id);
                self.persister.remove(rule_id)?;
                self.coordinator.complete_removal(rule_id);
                tracing::info!(%rule_id, "TTL expired, rule removed");
                Ok(())
            }
            Err(FirewallError::RuleNotFound(_)) => {
                // Rule already gone (manual removal)
                let mut registry = self.registry.write().unwrap();
                let _ = registry.mark_expired(rule_id);
                self.persister.remove(rule_id)?;
                self.coordinator.complete_removal(rule_id);
                tracing::debug!(%rule_id, "Rule already removed (TTL cleanup)");
                Ok(())
            }
            Err(e) => {
                // Failed - mark for retry
                let mut registry = self.registry.write().unwrap();
                let _ = registry.mark_failed(rule_id);
                self.persister.persist_update(rule_id, TtlState::Failed, entry.generation + 2)?;
                self.coordinator.release_removal(rule_id);
                Err(TtlError::FirewallError(e))
            }
        }
    }

    /// Reschedule the timer for the next expiration
    fn reschedule_timer(&self) {
        let registry = self.registry.read().unwrap();
        if let Some(next_exp) = registry.next_expiration() {
            self.next_wakeup_ms.store(next_exp, Ordering::SeqCst);
        } else {
            self.next_wakeup_ms.store(0, Ordering::SeqCst);
        }
    }

    /// Shutdown the TTL engine
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        tracing::info!("TTL engine shut down");
    }

    /// Compact the persistence log
    pub fn compact(&self) -> TtlResult<()> {
        let entries = {
            let registry = self.registry.read().unwrap();
            registry.list_active()
        };

        self.persister.compact(&entries)?;
        tracing::info!(entries = entries.len(), "Compacted TTL log");
        Ok(())
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current time in milliseconds since Unix epoch
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_entry_creation() {
        let entry = TtlEntry::new(RuleId::new("test-rule"), Duration::from_secs(3600));

        assert_eq!(entry.rule_id.as_str(), "test-rule");
        assert_eq!(entry.original_ttl_secs, 3600);
        assert_eq!(entry.state, TtlState::Active);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_ttl_entry_expired() {
        let mut entry = TtlEntry::new(RuleId::new("test"), Duration::from_secs(1));
        // Set expiration in the past
        entry.expires_at_ms = 1;

        assert!(entry.is_expired());
        assert!(entry.remaining().is_none());
    }

    #[test]
    fn test_ttl_entry_extend() {
        let mut entry = TtlEntry::new(RuleId::new("test"), Duration::from_secs(60));
        let original_gen = entry.generation;
        let original_exp = entry.expires_at_ms;

        entry.extend(Duration::from_secs(30));

        assert_eq!(entry.expires_at_ms, original_exp + 30_000);
        assert_eq!(entry.generation, original_gen + 1);
    }

    #[test]
    fn test_registry_basic_ops() {
        let mut registry = TtlRegistry::new();

        let entry1 = TtlEntry::new(RuleId::new("rule1"), Duration::from_secs(100));
        let entry2 = TtlEntry::new(RuleId::new("rule2"), Duration::from_secs(200));

        registry.register(entry1.clone()).unwrap();
        registry.register(entry2.clone()).unwrap();

        assert_eq!(registry.active_count(), 2);
        assert!(registry.get(&RuleId::new("rule1")).is_some());
    }

    #[test]
    fn test_registry_next_expiration() {
        let mut registry = TtlRegistry::new();

        let mut entry1 = TtlEntry::new(RuleId::new("rule1"), Duration::from_secs(100));
        entry1.expires_at_ms = 1000;
        let mut entry2 = TtlEntry::new(RuleId::new("rule2"), Duration::from_secs(200));
        entry2.expires_at_ms = 500;

        registry.register(entry1).unwrap();
        registry.register(entry2).unwrap();

        // Soonest expiration should be 500
        assert_eq!(registry.next_expiration(), Some(500));
    }

    #[test]
    fn test_registry_entries_expiring_before() {
        let mut registry = TtlRegistry::new();

        let mut entry1 = TtlEntry::new(RuleId::new("rule1"), Duration::from_secs(100));
        entry1.expires_at_ms = 1000;
        let mut entry2 = TtlEntry::new(RuleId::new("rule2"), Duration::from_secs(200));
        entry2.expires_at_ms = 500;
        let mut entry3 = TtlEntry::new(RuleId::new("rule3"), Duration::from_secs(300));
        entry3.expires_at_ms = 2000;

        registry.register(entry1).unwrap();
        registry.register(entry2).unwrap();
        registry.register(entry3).unwrap();

        let expired = registry.entries_expiring_before(1000);
        assert_eq!(expired.len(), 2);

        let expired = registry.entries_expiring_before(500);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn test_registry_cancel() {
        let mut registry = TtlRegistry::new();

        let entry = TtlEntry::new(RuleId::new("rule1"), Duration::from_secs(100));
        registry.register(entry).unwrap();

        assert_eq!(registry.active_count(), 1);

        let cancelled = registry.cancel(&RuleId::new("rule1"));
        assert!(cancelled.is_some());
        assert_eq!(cancelled.unwrap().state, TtlState::Cancelled);
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_coordinator_ttl_acquisition() {
        let coordinator = TtlRollbackCoordinator::new();
        let rule_id = RuleId::new("test-rule");

        // First acquisition should succeed
        assert!(coordinator.try_acquire_ttl_removal(&rule_id).is_ok());

        // Second acquisition should fail (already removing)
        assert_eq!(
            coordinator.try_acquire_ttl_removal(&rule_id),
            Err(CoordinationError::AlreadyRemoving)
        );

        // Complete the removal
        coordinator.complete_removal(&rule_id);

        // Now it should be marked as removed
        assert_eq!(
            coordinator.try_acquire_ttl_removal(&rule_id),
            Err(CoordinationError::AlreadyRemoved)
        );
    }

    #[test]
    fn test_coordinator_rollback_blocks_ttl() {
        let coordinator = TtlRollbackCoordinator::new();
        let rule_id = RuleId::new("test-rule");

        // Begin rollback
        coordinator.begin_rollback();

        // TTL acquisition should fail
        assert_eq!(
            coordinator.try_acquire_ttl_removal(&rule_id),
            Err(CoordinationError::RollbackInProgress)
        );

        // End rollback
        coordinator.end_rollback();

        // Now TTL should work
        assert!(coordinator.try_acquire_ttl_removal(&rule_id).is_ok());
    }

    #[test]
    fn test_coordinator_ttl_blocks_rollback() {
        let coordinator = TtlRollbackCoordinator::new();
        let rule_id = RuleId::new("test-rule");

        // TTL acquires first
        assert!(coordinator.try_acquire_ttl_removal(&rule_id).is_ok());

        // Rollback should fail for this rule
        assert_eq!(
            coordinator.try_acquire_rollback_removal(&rule_id),
            Err(CoordinationError::TtlInProgress)
        );
    }
}
