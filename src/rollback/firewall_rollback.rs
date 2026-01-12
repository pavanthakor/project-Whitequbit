//! Firewall Rollback Engine
//!
//! Provides comprehensive tracking and rollback capabilities for firewall rules.
//! Key properties:
//!
//! - **Complete tracking**: Every rule associated with action ID, timestamp, version
//! - **Automatic rollback**: Failed actions trigger automatic rollback
//! - **Manual rollback**: API for operator-initiated rollback
//! - **Rule isolation**: Only removes rules created by this agent
//! - **Idempotent**: Multiple rollback attempts produce same result
//!
//! See `docs/ROLLBACK_ENGINE.md` for detailed design.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;

use crate::actions::ActionId;
use crate::firewall::{FirewallBackend, FirewallError, FirewallRuleSpec, RuleId};
use crate::firewall::ttl::{CoordinationError, TtlRollbackCoordinator};
use crate::rollback::{JournalEntryId, RollbackError};

// ============================================================================
// Error Types
// ============================================================================

/// Errors from rollback engine operations
#[derive(Error, Debug)]
pub enum RollbackEngineError {
    /// Rule not found in registry
    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    /// Action not found
    #[error("Action not found: {0}")]
    ActionNotFound(String),

    /// Invalid state transition
    #[error("Invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition {
        /// Source state
        from: RuleRecordState,
        /// Target state
        to: RuleRecordState,
    },

    /// Coordination error with TTL
    #[error("Coordination error: {0}")]
    CoordinationError(String),

    /// Firewall backend error
    #[error("Firewall error: {0}")]
    FirewallError(#[from] FirewallError),

    /// IO error during persistence
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Rollback already in progress
    #[error("Rollback already in progress: {0}")]
    RollbackInProgress(String),

    /// Rollback error from base module
    #[error("Rollback error: {0}")]
    RollbackError(#[from] RollbackError),
}

/// Result type for rollback engine operations
pub type RollbackEngineResult<T> = Result<T, RollbackEngineError>;

// ============================================================================
// Rule Record
// ============================================================================

/// State of a rule record
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleRecordState {
    /// Rule is active in the firewall
    Active,
    /// Rollback in progress
    RollingBack,
    /// Successfully rolled back
    RolledBack,
    /// Rollback failed, requires manual intervention
    RollbackFailed,
    /// Expired via TTL
    Expired,
    /// Manually removed (external to agent)
    ManuallyRemoved,
}

/// Complete record of a firewall rule applied by this agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleRecord {
    /// Unique rule identifier
    pub rule_id: RuleId,

    /// Action that created this rule
    pub action_id: ActionId,

    /// Journal entry for this rule's action
    pub journal_entry_id: JournalEntryId,

    /// When the rule was created (Unix timestamp ms)
    pub created_at_ms: u64,

    /// Monotonic version number (for ordering)
    pub version: u64,

    /// The complete rule specification
    pub spec: FirewallRuleSpec,

    /// Current state of this record
    pub state: RuleRecordState,

    /// TTL expiration (if temporary rule)
    pub expires_at_ms: Option<u64>,

    /// Generation for CAS operations
    pub generation: u64,

    /// Checksum for integrity verification
    pub checksum: String,
}

impl FirewallRuleRecord {
    /// Create a new rule record
    pub fn new(
        rule_id: RuleId,
        action_id: ActionId,
        journal_entry_id: JournalEntryId,
        spec: FirewallRuleSpec,
        version: u64,
    ) -> Self {
        let now_ms = current_time_ms();
        let expires_at_ms = spec.ttl.map(|ttl| now_ms + ttl.as_millis() as u64);
        
        let mut record = Self {
            rule_id,
            action_id,
            journal_entry_id,
            created_at_ms: now_ms,
            version,
            spec,
            state: RuleRecordState::Active,
            expires_at_ms,
            generation: 1,
            checksum: String::new(),
        };
        record.checksum = record.compute_checksum();
        record
    }

    /// Compute integrity checksum
    fn compute_checksum(&self) -> String {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(self.rule_id.as_str().as_bytes());
        hasher.update(self.action_id.to_string().as_bytes());
        hasher.update(&self.journal_entry_id.as_u64().to_le_bytes());
        hasher.update(&self.created_at_ms.to_le_bytes());
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&[self.state as u8]);
        hasher.finalize().to_hex().to_string()
    }

    /// Verify integrity
    pub fn verify(&self) -> bool {
        self.checksum == self.compute_checksum()
    }

    /// Update state and generation
    fn transition(&mut self, new_state: RuleRecordState) {
        self.state = new_state;
        self.generation += 1;
        self.checksum = self.compute_checksum();
    }

    /// Check if this record needs rollback
    pub fn needs_rollback(&self) -> bool {
        matches!(
            self.state,
            RuleRecordState::Active | RuleRecordState::RollingBack | RuleRecordState::RollbackFailed
        )
    }
}

// ============================================================================
// Rule Registry
// ============================================================================

/// In-memory registry of all firewall rules created by this agent
pub struct RuleRegistry {
    /// Primary index: rule_id → record
    by_rule_id: HashMap<RuleId, FirewallRuleRecord>,

    /// Index by action: action_id → Vec<rule_id>
    by_action_id: HashMap<ActionId, Vec<RuleId>>,

    /// Index by journal entry: journal_entry_id → Vec<rule_id>
    by_journal_entry: HashMap<JournalEntryId, Vec<RuleId>>,

    /// Time-ordered index for version-based lookups
    by_version: BTreeMap<u64, RuleId>,

    /// Global version counter
    next_version: AtomicU64,

    /// Registry version for change detection
    registry_version: AtomicU64,
}

impl RuleRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            by_rule_id: HashMap::new(),
            by_action_id: HashMap::new(),
            by_journal_entry: HashMap::new(),
            by_version: BTreeMap::new(),
            next_version: AtomicU64::new(1),
            registry_version: AtomicU64::new(0),
        }
    }

    /// Get next version number
    pub fn next_version(&self) -> u64 {
        self.next_version.fetch_add(1, Ordering::SeqCst)
    }

    /// Register a new rule
    pub fn register(&mut self, record: FirewallRuleRecord) -> RollbackEngineResult<()> {
        let rule_id = record.rule_id.clone();
        let action_id = record.action_id.clone();
        let journal_entry_id = record.journal_entry_id;
        let version = record.version;

        // Add to primary index
        self.by_rule_id.insert(rule_id.clone(), record);

        // Add to action index
        self.by_action_id
            .entry(action_id)
            .or_default()
            .push(rule_id.clone());

        // Add to journal entry index
        self.by_journal_entry
            .entry(journal_entry_id)
            .or_default()
            .push(rule_id.clone());

        // Add to version index
        self.by_version.insert(version, rule_id);

        self.registry_version.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Get a rule by ID
    pub fn get(&self, rule_id: &RuleId) -> Option<&FirewallRuleRecord> {
        self.by_rule_id.get(rule_id)
    }

    /// Get a mutable rule by ID
    pub fn get_mut(&mut self, rule_id: &RuleId) -> Option<&mut FirewallRuleRecord> {
        self.by_rule_id.get_mut(rule_id)
    }

    /// Check if a rule exists
    pub fn contains(&self, rule_id: &RuleId) -> bool {
        self.by_rule_id.contains_key(rule_id)
    }

    /// Get all rules for an action
    pub fn get_by_action(&self, action_id: &ActionId) -> Vec<&FirewallRuleRecord> {
        self.by_action_id
            .get(action_id)
            .map(|ids| ids.iter().filter_map(|id| self.by_rule_id.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all rules for a journal entry
    pub fn get_by_journal_entry(&self, entry_id: JournalEntryId) -> Vec<&FirewallRuleRecord> {
        self.by_journal_entry
            .get(&entry_id)
            .map(|ids| ids.iter().filter_map(|id| self.by_rule_id.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get rules in version order (descending = LIFO)
    pub fn get_by_version_desc(&self) -> Vec<&FirewallRuleRecord> {
        self.by_version
            .values()
            .rev()
            .filter_map(|id| self.by_rule_id.get(id))
            .collect()
    }

    /// Get last N rules by version
    pub fn get_last_n(&self, count: usize) -> Vec<&FirewallRuleRecord> {
        self.by_version
            .values()
            .rev()
            .take(count)
            .filter_map(|id| self.by_rule_id.get(id))
            .collect()
    }

    /// Get rules in a time range
    pub fn get_by_time_range(&self, start_ms: u64, end_ms: u64) -> Vec<&FirewallRuleRecord> {
        self.by_rule_id
            .values()
            .filter(|r| r.created_at_ms >= start_ms && r.created_at_ms <= end_ms)
            .collect()
    }

    /// Get all active rules
    pub fn get_active(&self) -> Vec<&FirewallRuleRecord> {
        self.by_rule_id
            .values()
            .filter(|r| r.state == RuleRecordState::Active)
            .collect()
    }

    /// Get rules by state
    pub fn get_by_state(&self, state: RuleRecordState) -> Vec<&FirewallRuleRecord> {
        self.by_rule_id
            .values()
            .filter(|r| r.state == state)
            .collect()
    }

    /// Update rule state
    pub fn update_state(
        &mut self,
        rule_id: &RuleId,
        new_state: RuleRecordState,
    ) -> RollbackEngineResult<()> {
        let record = self
            .by_rule_id
            .get_mut(rule_id)
            .ok_or_else(|| RollbackEngineError::RuleNotFound(rule_id.to_string()))?;

        record.transition(new_state);
        self.registry_version.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Remove a rule record
    pub fn remove(&mut self, rule_id: &RuleId) -> Option<FirewallRuleRecord> {
        if let Some(record) = self.by_rule_id.remove(rule_id) {
            // Remove from action index
            if let Some(ids) = self.by_action_id.get_mut(&record.action_id) {
                ids.retain(|id| id != rule_id);
            }

            // Remove from journal entry index
            if let Some(ids) = self.by_journal_entry.get_mut(&record.journal_entry_id) {
                ids.retain(|id| id != rule_id);
            }

            // Remove from version index
            self.by_version.remove(&record.version);

            self.registry_version.fetch_add(1, Ordering::SeqCst);
            Some(record)
        } else {
            None
        }
    }

    /// Get count of active rules
    pub fn active_count(&self) -> usize {
        self.by_rule_id
            .values()
            .filter(|r| r.state == RuleRecordState::Active)
            .count()
    }

    /// Get total count
    pub fn total_count(&self) -> usize {
        self.by_rule_id.len()
    }

    /// Get all records
    pub fn all(&self) -> Vec<&FirewallRuleRecord> {
        self.by_rule_id.values().collect()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Rollback Scope
// ============================================================================

/// Scope of a rollback operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RollbackScope {
    /// Rollback a single action
    SingleAction {
        /// Action identifier
        action_id: ActionId,
    },
    /// Rollback a journal entry
    JournalEntry {
        /// Journal entry identifier
        entry_id: JournalEntryId,
    },
    /// Rollback specific rules by ID
    SpecificRules {
        /// List of rule IDs to rollback
        rule_ids: Vec<RuleId>,
    },
    /// Rollback last N rules (by version)
    LastN {
        /// Number of rules to rollback
        count: usize,
    },
    /// Rollback rules in time range
    TimeRange {
        /// Start timestamp in milliseconds
        start_ms: u64,
        /// End timestamp in milliseconds
        end_ms: u64,
    },
    /// Rollback all rules (emergency)
    All,
}

/// Unique identifier for a rollback operation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RollbackId(String);

impl RollbackId {
    /// Generate a new rollback ID
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Get as string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RollbackId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================================
// Rollback Results
// ============================================================================

/// Reason for rule removal
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalReason {
    /// Successfully rolled back
    RolledBack,
    /// Expired via TTL
    TtlExpired,
    /// Manually removed by operator
    ManualRemoval,
    /// Rule not found in firewall (external removal)
    ExternalRemoval,
}

/// Result of rolling back a single rule
#[derive(Debug, Clone)]
pub struct RuleRollbackResult {
    /// Rule that was rolled back
    pub rule_id: RuleId,
    /// Whether rollback succeeded
    pub success: bool,
    /// Whether rule was already removed (idempotent)
    pub was_already_removed: bool,
    /// Whether rollback was skipped
    pub skipped: bool,
    /// Reason for skip (if skipped)
    pub skip_reason: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

impl RuleRollbackResult {
    /// Create a success result
    pub fn success(rule_id: RuleId) -> Self {
        Self {
            rule_id,
            success: true,
            was_already_removed: false,
            skipped: false,
            skip_reason: None,
            error: None,
        }
    }

    /// Create an already-removed result
    pub fn already_removed(rule_id: RuleId) -> Self {
        Self {
            rule_id,
            success: true,
            was_already_removed: true,
            skipped: false,
            skip_reason: None,
            error: None,
        }
    }

    /// Create a skipped result
    pub fn skipped(rule_id: RuleId, reason: impl Into<String>) -> Self {
        Self {
            rule_id,
            success: true,
            was_already_removed: false,
            skipped: true,
            skip_reason: Some(reason.into()),
            error: None,
        }
    }

    /// Create a failure result
    pub fn failure(rule_id: RuleId, error: impl Into<String>) -> Self {
        Self {
            rule_id,
            success: false,
            was_already_removed: false,
            skipped: false,
            skip_reason: None,
            error: Some(error.into()),
        }
    }
}

/// Result of a complete rollback operation
#[derive(Debug)]
pub struct RollbackResult {
    /// Unique rollback operation ID
    pub rollback_id: RollbackId,
    /// Scope that was rolled back
    pub scope: RollbackScope,
    /// Total number of rules in scope
    pub total_rules: usize,
    /// Number of successfully rolled back rules
    pub succeeded: usize,
    /// Number of failed rollbacks
    pub failed: usize,
    /// Individual results for each rule
    pub results: Vec<RuleRollbackResult>,
    /// Whether manual intervention is required
    pub requires_intervention: bool,
}

impl RollbackResult {
    /// Create an empty result
    pub fn empty(rollback_id: RollbackId, scope: RollbackScope) -> Self {
        Self {
            rollback_id,
            scope,
            total_rules: 0,
            succeeded: 0,
            failed: 0,
            results: Vec::new(),
            requires_intervention: false,
        }
    }

    /// Check if rollback was completely successful
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Get failed rule IDs
    pub fn failed_rules(&self) -> Vec<RuleId> {
        self.results
            .iter()
            .filter(|r| !r.success)
            .map(|r| r.rule_id.clone())
            .collect()
    }
}

// ============================================================================
// Rollback Journal
// ============================================================================

/// Journal operations for rollback tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RollbackJournalOp {
    /// Rule was created
    RuleCreated {
        /// The created rule record
        record: FirewallRuleRecord,
    },
    /// Rule state changed
    StateChanged {
        /// Rule identifier
        rule_id: RuleId,
        /// Previous state
        old_state: RuleRecordState,
        /// New state
        new_state: RuleRecordState,
        /// Generation number
        generation: u64,
    },
    /// Rule was removed
    RuleRemoved {
        /// Rule identifier
        rule_id: RuleId,
        /// Reason for removal
        reason: RemovalReason,
    },
    /// Rollback started
    RollbackStarted {
        /// Rollback identifier
        rollback_id: RollbackId,
        /// Rollback scope
        scope: RollbackScope,
        /// Rules being rolled back
        rule_ids: Vec<RuleId>,
    },
    /// Rollback completed
    RollbackCompleted {
        /// Rollback identifier
        rollback_id: RollbackId,
        /// Whether rollback succeeded
        success: bool,
        /// List of rules that failed
        failed_rules: Vec<RuleId>,
    },
    /// Checkpoint marker
    Checkpoint {
        /// Sequence number checkpointed up to
        up_to_seq: u64,
        /// Number of active rules at checkpoint
        active_rule_count: usize,
    },
}

/// A single journal entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RollbackLogEntry {
    /// Monotonic sequence number
    seq: u64,
    /// Timestamp
    timestamp_ms: u64,
    /// The operation
    op: RollbackJournalOp,
}

/// Rollback journal for persistent tracking
pub struct RollbackJournal {
    /// Path to journal file
    path: PathBuf,
    /// Next sequence number
    next_seq: AtomicU64,
    /// Fsync after writes
    sync_writes: bool,
}

impl RollbackJournal {
    /// Create or open a journal
    pub fn new(path: impl AsRef<Path>) -> RollbackEngineResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Create parent directory
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Find max seq from existing file
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
    pub fn with_sync(path: impl AsRef<Path>, sync_writes: bool) -> RollbackEngineResult<Self> {
        let mut journal = Self::new(path)?;
        journal.sync_writes = sync_writes;
        Ok(journal)
    }

    /// Find max sequence number
    fn find_max_seq(path: &Path) -> RollbackEngineResult<u64> {
        use std::io::{BufRead, BufReader};

        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut max_seq = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<RollbackLogEntry>(&line) {
                max_seq = max_seq.max(entry.seq);
            }
        }

        Ok(max_seq)
    }

    /// Load all records from journal
    pub fn load(&self) -> RollbackEngineResult<Vec<FirewallRuleRecord>> {
        use std::io::{BufRead, BufReader};

        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(file);

        let mut records: HashMap<RuleId, FirewallRuleRecord> = HashMap::new();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let log_entry: RollbackLogEntry = serde_json::from_str(&line)
                .map_err(|e| RollbackEngineError::SerializationError(e.to_string()))?;

            match log_entry.op {
                RollbackJournalOp::RuleCreated { record } => {
                    records.insert(record.rule_id.clone(), record);
                }
                RollbackJournalOp::StateChanged {
                    rule_id,
                    new_state,
                    generation,
                    ..
                } => {
                    if let Some(record) = records.get_mut(&rule_id) {
                        if generation > record.generation {
                            record.state = new_state;
                            record.generation = generation;
                        }
                    }
                }
                RollbackJournalOp::RuleRemoved { rule_id, .. } => {
                    records.remove(&rule_id);
                }
                _ => {}
            }
        }

        Ok(records.into_values().collect())
    }

    /// Write an operation to the journal
    fn write_op(&self, op: RollbackJournalOp) -> RollbackEngineResult<()> {
        use std::io::Write;

        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let entry = RollbackLogEntry {
            seq,
            timestamp_ms: current_time_ms(),
            op,
        };

        let mut line = serde_json::to_string(&entry)
            .map_err(|e| RollbackEngineError::SerializationError(e.to_string()))?;
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

    /// Log rule creation
    pub fn log_rule_created(&self, record: &FirewallRuleRecord) -> RollbackEngineResult<()> {
        self.write_op(RollbackJournalOp::RuleCreated {
            record: record.clone(),
        })
    }

    /// Log state change
    pub fn log_state_changed(
        &self,
        rule_id: RuleId,
        old_state: RuleRecordState,
        new_state: RuleRecordState,
        generation: u64,
    ) -> RollbackEngineResult<()> {
        self.write_op(RollbackJournalOp::StateChanged {
            rule_id,
            old_state,
            new_state,
            generation,
        })
    }

    /// Log rule removal
    pub fn log_rule_removed(&self, rule_id: RuleId, reason: RemovalReason) -> RollbackEngineResult<()> {
        self.write_op(RollbackJournalOp::RuleRemoved { rule_id, reason })
    }

    /// Log rollback started
    pub fn log_rollback_started(
        &self,
        rollback_id: RollbackId,
        scope: RollbackScope,
        rule_ids: Vec<RuleId>,
    ) -> RollbackEngineResult<()> {
        self.write_op(RollbackJournalOp::RollbackStarted {
            rollback_id,
            scope,
            rule_ids,
        })
    }

    /// Log rollback completed
    pub fn log_rollback_completed(
        &self,
        rollback_id: RollbackId,
        success: bool,
        failed_rules: Vec<RuleId>,
    ) -> RollbackEngineResult<()> {
        self.write_op(RollbackJournalOp::RollbackCompleted {
            rollback_id,
            success,
            failed_rules,
        })
    }
}

// ============================================================================
// Rollback Engine
// ============================================================================

/// Configuration for the rollback engine
#[derive(Debug, Clone)]
pub struct RollbackEngineConfig {
    /// Path to rollback journal
    pub journal_path: PathBuf,
    /// Whether to fsync after writes
    pub sync_writes: bool,
    /// Maximum retries for failed rollbacks
    pub max_retries: usize,
    /// Delay between retries
    pub retry_delay: Duration,
}

impl Default for RollbackEngineConfig {
    fn default() -> Self {
        Self {
            journal_path: PathBuf::from("/var/lib/whitequbit/rollback.log"),
            sync_writes: true,
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
    }
}

/// The main rollback engine
pub struct RollbackEngine<B: FirewallBackend> {
    /// Rule registry
    registry: Arc<RwLock<RuleRegistry>>,
    /// Rollback journal
    journal: RollbackJournal,
    /// TTL coordinator
    coordinator: Arc<TtlRollbackCoordinator>,
    /// Firewall backend
    firewall: Arc<B>,
    /// Configuration
    #[allow(dead_code)]
    config: RollbackEngineConfig,
}

impl<B: FirewallBackend> RollbackEngine<B> {
    /// Create a new rollback engine
    pub fn new(
        config: RollbackEngineConfig,
        firewall: Arc<B>,
        coordinator: Arc<TtlRollbackCoordinator>,
    ) -> RollbackEngineResult<Self> {
        let journal = RollbackJournal::with_sync(&config.journal_path, config.sync_writes)?;

        Ok(Self {
            registry: Arc::new(RwLock::new(RuleRegistry::new())),
            journal,
            coordinator,
            firewall,
            config,
        })
    }

    /// Recover state from journal
    #[instrument(skip(self))]
    pub fn recover(&self) -> RollbackEngineResult<RecoveryStats> {
        tracing::info!("Recovering rollback state from journal");
        let mut stats = RecoveryStats::default();

        let records = self.journal.load()?;
        stats.loaded = records.len();

        let mut registry = self.registry.write().unwrap();

        for record in records {
            match record.state {
                RuleRecordState::Active => {
                    registry.register(record)?;
                    stats.active += 1;
                }
                RuleRecordState::RollingBack => {
                    // Interrupted rollback - add for retry
                    registry.register(record)?;
                    stats.interrupted += 1;
                }
                RuleRecordState::RollbackFailed => {
                    // Needs manual intervention
                    registry.register(record)?;
                    stats.failed += 1;
                }
                RuleRecordState::RolledBack
                | RuleRecordState::Expired
                | RuleRecordState::ManuallyRemoved => {
                    // Terminal states - don't add to registry
                    stats.terminal += 1;
                }
            }
        }

        tracing::info!(?stats, "Recovery complete");
        Ok(stats)
    }

    /// Register a newly created rule
    pub fn register_rule(
        &self,
        rule_id: RuleId,
        action_id: ActionId,
        journal_entry_id: JournalEntryId,
        spec: FirewallRuleSpec,
    ) -> RollbackEngineResult<()> {
        let version = {
            let registry = self.registry.read().unwrap();
            registry.next_version.load(Ordering::SeqCst)
        };

        let record = FirewallRuleRecord::new(
            rule_id.clone(),
            action_id,
            journal_entry_id,
            spec,
            version,
        );

        // Persist first
        self.journal.log_rule_created(&record)?;

        // Then add to registry
        let mut registry = self.registry.write().unwrap();
        registry.register(record)?;

        tracing::info!(%rule_id, "Registered rule for rollback tracking");
        Ok(())
    }

    /// Execute a rollback operation
    #[instrument(skip(self))]
    pub async fn execute_rollback(&self, scope: RollbackScope) -> RollbackEngineResult<RollbackResult> {
        let rollback_id = RollbackId::generate();
        tracing::info!(%rollback_id, ?scope, "Starting rollback");

        // Notify coordinator that rollback is starting
        self.coordinator.begin_rollback();

        let result = self.execute_rollback_inner(rollback_id.clone(), scope.clone()).await;

        // Notify coordinator that rollback is complete
        self.coordinator.end_rollback();

        result
    }

    async fn execute_rollback_inner(
        &self,
        rollback_id: RollbackId,
        scope: RollbackScope,
    ) -> RollbackEngineResult<RollbackResult> {
        // 1. Resolve scope to rules
        let rules = self.resolve_scope(&scope)?;

        if rules.is_empty() {
            tracing::info!(%rollback_id, "No rules to rollback");
            return Ok(RollbackResult::empty(rollback_id, scope));
        }

        let rule_ids: Vec<RuleId> = rules.iter().map(|r| r.rule_id.clone()).collect();

        // 2. Log rollback start
        self.journal.log_rollback_started(
            rollback_id.clone(),
            scope.clone(),
            rule_ids.clone(),
        )?;

        // 3. Sort by version descending (LIFO)
        let mut rules = rules;
        rules.sort_by(|a, b| b.version.cmp(&a.version));

        // 4. Execute rollback for each rule
        let mut results = Vec::new();
        let mut failed_rules = Vec::new();

        for record in &rules {
            match self.rollback_single_rule(record).await {
                Ok(result) => {
                    if !result.success {
                        failed_rules.push(record.rule_id.clone());
                    }
                    results.push(result);
                }
                Err(e) => {
                    tracing::warn!(rule_id = %record.rule_id, error = %e, "Rollback failed");
                    failed_rules.push(record.rule_id.clone());
                    results.push(RuleRollbackResult::failure(record.rule_id.clone(), e.to_string()));
                }
            }
        }

        // 5. Log rollback complete
        let success = failed_rules.is_empty();
        self.journal.log_rollback_completed(rollback_id.clone(), success, failed_rules.clone())?;

        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = failed_rules.len();

        tracing::info!(
            %rollback_id,
            total = rules.len(),
            succeeded,
            failed,
            "Rollback complete"
        );

        Ok(RollbackResult {
            rollback_id,
            scope,
            total_rules: rules.len(),
            succeeded,
            failed,
            results,
            requires_intervention: !failed_rules.is_empty(),
        })
    }

    /// Resolve rollback scope to rules
    fn resolve_scope(&self, scope: &RollbackScope) -> RollbackEngineResult<Vec<FirewallRuleRecord>> {
        let registry = self.registry.read().unwrap();

        let records = match scope {
            RollbackScope::SingleAction { action_id } => {
                registry.get_by_action(action_id)
                    .into_iter()
                    .filter(|r| r.needs_rollback())
                    .cloned()
                    .collect()
            }
            RollbackScope::JournalEntry { entry_id } => {
                registry.get_by_journal_entry(*entry_id)
                    .into_iter()
                    .filter(|r| r.needs_rollback())
                    .cloned()
                    .collect()
            }
            RollbackScope::SpecificRules { rule_ids } => {
                rule_ids.iter()
                    .filter_map(|id| registry.get(id))
                    .filter(|r| r.needs_rollback())
                    .cloned()
                    .collect()
            }
            RollbackScope::LastN { count } => {
                registry.get_last_n(*count)
                    .into_iter()
                    .filter(|r| r.needs_rollback())
                    .cloned()
                    .collect()
            }
            RollbackScope::TimeRange { start_ms, end_ms } => {
                registry.get_by_time_range(*start_ms, *end_ms)
                    .into_iter()
                    .filter(|r| r.needs_rollback())
                    .cloned()
                    .collect()
            }
            RollbackScope::All => {
                registry.get_active()
                    .into_iter()
                    .cloned()
                    .collect()
            }
        };

        Ok(records)
    }

    /// Rollback a single rule
    async fn rollback_single_rule(
        &self,
        record: &FirewallRuleRecord,
    ) -> RollbackEngineResult<RuleRollbackResult> {
        let rule_id = &record.rule_id;

        // 1. Acquire coordination lock
        match self.coordinator.try_acquire_rollback_removal(rule_id) {
            Ok(()) => {}
            Err(CoordinationError::TtlInProgress) => {
                tracing::debug!(%rule_id, "TTL already removing rule, skipping");
                return Ok(RuleRollbackResult::skipped(rule_id.clone(), "TTL in progress"));
            }
            Err(CoordinationError::AlreadyRemoved) => {
                self.update_state(rule_id, RuleRecordState::ManuallyRemoved)?;
                return Ok(RuleRollbackResult::already_removed(rule_id.clone()));
            }
            Err(e) => {
                return Err(RollbackEngineError::CoordinationError(e.to_string()));
            }
        }

        // 2. Update state: → RollingBack
        let old_state = record.state;
        self.update_state(rule_id, RuleRecordState::RollingBack)?;
        self.journal.log_state_changed(
            rule_id.clone(),
            old_state,
            RuleRecordState::RollingBack,
            record.generation + 1,
        )?;

        // 3. Remove via firewall backend
        let result = self.firewall.remove_rule(rule_id).await;

        match result {
            Ok(_) => {
                // Success
                self.update_state(rule_id, RuleRecordState::RolledBack)?;
                self.journal.log_rule_removed(rule_id.clone(), RemovalReason::RolledBack)?;
                self.coordinator.complete_removal(rule_id);
                tracing::info!(%rule_id, "Rule rolled back successfully");
                Ok(RuleRollbackResult::success(rule_id.clone()))
            }
            Err(FirewallError::RuleNotFound(_)) => {
                // Rule doesn't exist - idempotent success
                self.update_state(rule_id, RuleRecordState::ManuallyRemoved)?;
                self.journal.log_rule_removed(rule_id.clone(), RemovalReason::ExternalRemoval)?;
                self.coordinator.complete_removal(rule_id);
                tracing::info!(%rule_id, "Rule already removed (idempotent)");
                Ok(RuleRollbackResult::already_removed(rule_id.clone()))
            }
            Err(e) => {
                // Failure
                self.update_state(rule_id, RuleRecordState::RollbackFailed)?;
                self.journal.log_state_changed(
                    rule_id.clone(),
                    RuleRecordState::RollingBack,
                    RuleRecordState::RollbackFailed,
                    record.generation + 2,
                )?;
                self.coordinator.release_removal(rule_id);
                tracing::error!(%rule_id, error = %e, "Rollback failed");
                Err(RollbackEngineError::FirewallError(e))
            }
        }
    }

    /// Update rule state in registry
    fn update_state(&self, rule_id: &RuleId, new_state: RuleRecordState) -> RollbackEngineResult<()> {
        let mut registry = self.registry.write().unwrap();
        registry.update_state(rule_id, new_state)
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Rollback a specific action by ID
    pub async fn rollback_action(&self, action_id: ActionId) -> RollbackEngineResult<RollbackResult> {
        self.execute_rollback(RollbackScope::SingleAction { action_id }).await
    }

    /// Rollback specific rules by ID
    pub async fn rollback_rules(&self, rule_ids: Vec<RuleId>) -> RollbackEngineResult<RollbackResult> {
        self.execute_rollback(RollbackScope::SpecificRules { rule_ids }).await
    }

    /// Rollback last N rules
    pub async fn rollback_last_n(&self, count: usize) -> RollbackEngineResult<RollbackResult> {
        self.execute_rollback(RollbackScope::LastN { count }).await
    }

    /// Rollback rules in time range
    pub async fn rollback_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> RollbackEngineResult<RollbackResult> {
        self.execute_rollback(RollbackScope::TimeRange {
            start_ms: start.timestamp_millis() as u64,
            end_ms: end.timestamp_millis() as u64,
        }).await
    }

    /// Emergency: rollback all rules
    pub async fn rollback_all(&self) -> RollbackEngineResult<RollbackResult> {
        tracing::warn!("Emergency rollback of ALL rules initiated");
        self.execute_rollback(RollbackScope::All).await
    }

    /// Preview rollback (query affected rules without executing)
    pub fn preview_rollback(&self, scope: &RollbackScope) -> RollbackEngineResult<Vec<FirewallRuleRecord>> {
        self.resolve_scope(scope)
    }

    /// Get rules requiring manual intervention
    pub fn get_failed_rollbacks(&self) -> Vec<FirewallRuleRecord> {
        let registry = self.registry.read().unwrap();
        registry.get_by_state(RuleRecordState::RollbackFailed)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Retry failed rollbacks
    pub async fn retry_failed(&self) -> RollbackEngineResult<RollbackResult> {
        let failed = self.get_failed_rollbacks();
        let rule_ids = failed.iter().map(|r| r.rule_id.clone()).collect();
        self.execute_rollback(RollbackScope::SpecificRules { rule_ids }).await
    }

    /// Notify that a rule was expired by TTL
    pub fn notify_ttl_expired(&self, rule_id: &RuleId) {
        let mut registry = self.registry.write().unwrap();
        if let Some(record) = registry.get_mut(rule_id) {
            record.transition(RuleRecordState::Expired);
            let _ = self.journal.log_rule_removed(rule_id.clone(), RemovalReason::TtlExpired);
        }
    }

    /// Get active rule count
    pub fn active_count(&self) -> usize {
        let registry = self.registry.read().unwrap();
        registry.active_count()
    }

    /// Get all active rules
    pub fn get_active_rules(&self) -> Vec<FirewallRuleRecord> {
        let registry = self.registry.read().unwrap();
        registry.get_active().into_iter().cloned().collect()
    }
}

// ============================================================================
// Recovery Stats
// ============================================================================

/// Statistics from recovery
#[derive(Debug, Default)]
pub struct RecoveryStats {
    /// Total records loaded from journal
    pub loaded: usize,
    /// Active rules
    pub active: usize,
    /// Interrupted rollbacks (need retry)
    pub interrupted: usize,
    /// Failed rollbacks (need intervention)
    pub failed: usize,
    /// Terminal state records (skipped)
    pub terminal: usize,
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current time in milliseconds
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
    fn test_rule_record_state_transitions() {
        let spec = FirewallRuleSpec {
            id: RuleId::generate(),
            source: None,
            destination: None,
            protocol: crate::firewall::Protocol::All,
            port: None,
            direction: crate::firewall::Direction::Inbound,
            action: crate::firewall::RuleAction::Block,
            rate_limit: None,
            ttl: None,
            comment: None,
            priority: 100,
        };

        let mut record = FirewallRuleRecord::new(
            RuleId::new("test-rule"),
            ActionId::new(),
            JournalEntryId::new(1),
            spec,
            1,
        );

        assert_eq!(record.state, RuleRecordState::Active);
        assert!(record.needs_rollback());

        record.transition(RuleRecordState::RollingBack);
        assert_eq!(record.state, RuleRecordState::RollingBack);
        assert!(record.needs_rollback());

        record.transition(RuleRecordState::RolledBack);
        assert_eq!(record.state, RuleRecordState::RolledBack);
        assert!(!record.needs_rollback());
    }

    #[test]
    fn test_rule_registry_basic_ops() {
        let mut registry = RuleRegistry::new();

        let spec = FirewallRuleSpec {
            id: RuleId::generate(),
            source: None,
            destination: None,
            protocol: crate::firewall::Protocol::All,
            port: None,
            direction: crate::firewall::Direction::Inbound,
            action: crate::firewall::RuleAction::Block,
            rate_limit: None,
            ttl: None,
            comment: None,
            priority: 100,
        };

        let action_id = ActionId::new();
        let record = FirewallRuleRecord::new(
            RuleId::new("rule-1"),
            action_id.clone(),
            JournalEntryId::new(1),
            spec,
            1,
        );

        registry.register(record).unwrap();

        assert_eq!(registry.total_count(), 1);
        assert_eq!(registry.active_count(), 1);
        assert!(registry.contains(&RuleId::new("rule-1")));

        let by_action = registry.get_by_action(&action_id);
        assert_eq!(by_action.len(), 1);
    }

    #[test]
    fn test_registry_lifo_order() {
        let mut registry = RuleRegistry::new();

        for i in 1..=5 {
            let spec = FirewallRuleSpec {
                id: RuleId::generate(),
                source: None,
                destination: None,
                protocol: crate::firewall::Protocol::All,
                port: None,
                direction: crate::firewall::Direction::Inbound,
                action: crate::firewall::RuleAction::Block,
                rate_limit: None,
                ttl: None,
                comment: None,
                priority: 100,
            };

            let version = registry.next_version();
            let record = FirewallRuleRecord::new(
                RuleId::new(format!("rule-{}", i)),
                ActionId::new(),
                JournalEntryId::new(i),
                spec,
                version,
            );
            registry.register(record).unwrap();
        }

        let ordered = registry.get_by_version_desc();
        assert_eq!(ordered.len(), 5);

        // Should be in descending version order (LIFO)
        for i in 0..4 {
            assert!(ordered[i].version > ordered[i + 1].version);
        }
    }

    #[test]
    fn test_rollback_result_success() {
        let result = RuleRollbackResult::success(RuleId::new("test"));
        assert!(result.success);
        assert!(!result.was_already_removed);
        assert!(!result.skipped);
    }

    #[test]
    fn test_rollback_result_already_removed() {
        let result = RuleRollbackResult::already_removed(RuleId::new("test"));
        assert!(result.success);
        assert!(result.was_already_removed);
    }

    #[test]
    fn test_rollback_id_generation() {
        let id1 = RollbackId::generate();
        let id2 = RollbackId::generate();
        assert_ne!(id1, id2);
    }
}
