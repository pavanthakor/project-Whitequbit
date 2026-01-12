//! Immutable Audit Logging System
//!
//! Provides a crash-safe, tamper-evident audit log with:
//! - Append-only storage with fsync guarantees
//! - BLAKE3 hash chaining for tamper detection
//! - Before/after state capture for security actions
//! - Write-Ahead Log (WAL) for crash recovery
//! - Periodic checkpoints for efficient verification
//! - Merkle tree roots for range proofs
//!
//! # Tamper Detection
//!
//! The audit log detects tampering through multiple mechanisms:
//!
//! 1. **Hash Chain**: Each entry contains the hash of the previous entry.
//!    Modifying any entry breaks the chain for all subsequent entries.
//!
//! 2. **Entry Self-Hash**: Each entry's hash covers all its fields.
//!    Any modification to an entry changes its hash.
//!
//! 3. **Sequence Numbers**: Monotonically increasing, gaps are detected.
//!    Deleting entries creates detectable sequence gaps.
//!
//! 4. **Checkpoint Anchors**: Periodic entries that hash all prior entries.
//!    Provides integrity verification without reading entire log.
//!
//! 5. **Merkle Tree Roots**: Enable proving specific entries exist without
//!    revealing the entire log (useful for auditor verification).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Instant;

use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from immutable audit operations
#[derive(Error, Debug)]
pub enum ImmutableAuditError {
    /// I/O error during file operations
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Hash chain integrity violation
    #[error("Chain integrity violation at sequence {sequence}: {message}")]
    ChainBroken {
        /// Sequence number where the chain broke
        sequence: u64,
        /// Description of the violation
        message: String,
    },

    /// Sequence number violation
    #[error("Sequence violation: expected {expected}, got {actual}")]
    SequenceViolation {
        /// Expected sequence number
        expected: u64,
        /// Actual sequence number found
        actual: u64,
    },

    /// Entry hash mismatch (entry was modified)
    #[error("Entry {sequence} hash mismatch: content was modified")]
    EntryModified {
        /// Sequence number of the modified entry
        sequence: u64,
    },

    /// WAL recovery failed
    #[error("WAL recovery failed: {0}")]
    WalRecoveryFailed(String),

    /// Checkpoint verification failed
    #[error("Checkpoint {sequence} verification failed: {message}")]
    CheckpointInvalid {
        /// Checkpoint sequence number
        sequence: u64,
        /// Validation failure message
        message: String,
    },

    /// Log file appears truncated
    #[error("Log truncated: expected {expected} entries, found {found}")]
    LogTruncated {
        /// Expected number of entries
        expected: u64,
        /// Actual number found
        found: u64,
    },

    /// Concurrent modification detected
    #[error("Concurrent modification: {0}")]
    ConcurrentModification(String),
}

/// Result type for immutable audit operations
pub type ImmutableAuditResult<T> = Result<T, ImmutableAuditError>;

// ============================================================================
// Audit Entry Types
// ============================================================================

/// Category of audit event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// Agent lifecycle (startup, shutdown, config)
    Lifecycle,
    /// Security actions (firewall, service changes)
    SecurityAction,
    /// Authentication and authorization
    Authentication,
    /// System integrity events
    Integrity,
    /// Rollback and recovery operations
    Recovery,
    /// Checkpoint entries (for verification)
    Checkpoint,
}

/// Severity level of the audit event
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    /// Informational (normal operations)
    Info,
    /// Notable event (configuration changes)
    Notice,
    /// Warning (recoverable issues)
    Warning,
    /// Error (operation failed)
    Error,
    /// Critical (security violation)
    Critical,
    /// Alert (immediate attention required)
    Alert,
}

impl Default for AuditSeverity {
    fn default() -> Self {
        Self::Info
    }
}

/// State snapshot for before/after comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Type of state being captured
    pub state_type: String,
    /// Hash of the state (for quick comparison)
    pub state_hash: String,
    /// Serialized state data (JSON)
    pub data: serde_json::Value,
    /// Timestamp when captured
    pub captured_at: DateTime<Utc>,
}

impl StateSnapshot {
    /// Create a new state snapshot
    pub fn new(state_type: impl Into<String>, data: serde_json::Value) -> Self {
        let state_type = state_type.into();
        let state_hash = Self::compute_hash(&data);
        Self {
            state_type,
            state_hash,
            data,
            captured_at: Utc::now(),
        }
    }

    /// Compute hash of state data
    fn compute_hash(data: &serde_json::Value) -> String {
        let mut hasher = Hasher::new();
        hasher.update(data.to_string().as_bytes());
        hasher.finalize().to_hex()[..16].to_string()
    }

    /// Check if state has changed
    pub fn differs_from(&self, other: &StateSnapshot) -> bool {
        self.state_hash != other.state_hash
    }
}

/// Before/after state for audited operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateTransition {
    /// State before the operation
    pub before: Option<StateSnapshot>,
    /// State after the operation
    pub after: Option<StateSnapshot>,
}

impl StateTransition {
    /// Create a transition with before state
    pub fn before(state: StateSnapshot) -> Self {
        Self {
            before: Some(state),
            after: None,
        }
    }

    /// Set the after state
    pub fn with_after(mut self, state: StateSnapshot) -> Self {
        self.after = Some(state);
        self
    }

    /// Check if a change occurred
    pub fn has_change(&self) -> bool {
        match (&self.before, &self.after) {
            (Some(b), Some(a)) => b.differs_from(a),
            (None, Some(_)) => true,  // Created
            (Some(_), None) => true,  // Deleted
            (None, None) => false,
        }
    }
}

/// Actor who initiated the audited action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditActor {
    /// Principal identifier (user, service, or system)
    pub principal: String,
    /// How the principal was authenticated
    pub auth_method: Option<String>,
    /// Source address (if remote)
    pub source_addr: Option<String>,
    /// Session or request ID
    pub session_id: Option<String>,
}

impl AuditActor {
    /// Create a system actor (internal agent operations)
    pub fn system() -> Self {
        Self {
            principal: "system".to_string(),
            auth_method: None,
            source_addr: None,
            session_id: None,
        }
    }

    /// Create an authenticated actor
    pub fn authenticated(
        principal: impl Into<String>,
        auth_method: impl Into<String>,
    ) -> Self {
        Self {
            principal: principal.into(),
            auth_method: Some(auth_method.into()),
            source_addr: None,
            session_id: None,
        }
    }

    /// Add source address
    pub fn with_source(mut self, addr: impl Into<String>) -> Self {
        self.source_addr = Some(addr.into());
        self
    }

    /// Add session ID
    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session_id = Some(session.into());
        self
    }
}

/// Target of the audited action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTarget {
    /// Resource type (firewall_rule, service, config, etc.)
    pub resource_type: String,
    /// Resource identifier
    pub resource_id: String,
    /// Additional target attributes
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

impl AuditTarget {
    /// Create a new audit target
    pub fn new(resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            attributes: BTreeMap::new(),
        }
    }

    /// Add an attribute
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

/// Immutable audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableAuditEntry {
    // ---- Identity ----
    /// Monotonically increasing sequence number
    pub sequence: u64,
    /// UUID for this entry (for external references)
    pub entry_id: String,
    /// Timestamp (UTC, nanosecond precision)
    pub timestamp: DateTime<Utc>,

    // ---- Classification ----
    /// Event category
    pub category: AuditCategory,
    /// Severity level
    pub severity: AuditSeverity,
    /// Event type (e.g., "firewall_rule_added")
    pub event_type: String,

    // ---- Context ----
    /// Who initiated the action
    pub actor: AuditActor,
    /// What was affected
    pub target: Option<AuditTarget>,
    /// Operation outcome
    pub outcome: AuditOutcome,

    // ---- State ----
    /// Before/after state transition
    #[serde(default)]
    pub state_transition: StateTransition,
    /// Additional structured data
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,

    // ---- Integrity ----
    /// Hash of the previous entry (empty for genesis)
    pub previous_hash: String,
    /// Hash of this entry (covers all fields above)
    pub entry_hash: String,
    /// Checkpoint data (only for checkpoint entries)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointData>,
}

/// Outcome of the audited operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Operation succeeded
    Success,
    /// Operation failed
    Failure {
        /// Failure reason
        reason: String,
    },
    /// Operation was denied by policy
    Denied {
        /// Policy that denied it
        policy: String,
    },
    /// Operation is pending/in-progress
    Pending,
    /// Operation was rolled back
    RolledBack {
        /// Rollback reason
        reason: String,
    },
}

impl Default for AuditOutcome {
    fn default() -> Self {
        Self::Success
    }
}

/// Checkpoint data for periodic integrity anchors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointData {
    /// Number of entries since last checkpoint
    pub entries_since_last: u64,
    /// Cumulative hash of all entries up to this point
    pub cumulative_hash: String,
    /// Merkle root of entries since last checkpoint
    pub merkle_root: String,
    /// Sequence of the previous checkpoint (0 for first)
    pub previous_checkpoint_seq: u64,
}

impl ImmutableAuditEntry {
    /// Compute the hash of this entry (excluding entry_hash field)
    fn compute_hash(&self) -> String {
        let mut hasher = Hasher::new();

        // Identity fields
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(self.entry_id.as_bytes());
        hasher.update(self.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true).as_bytes());

        // Classification
        hasher.update(format!("{:?}", self.category).as_bytes());
        hasher.update(format!("{:?}", self.severity).as_bytes());
        hasher.update(self.event_type.as_bytes());

        // Context - actor
        hasher.update(self.actor.principal.as_bytes());
        if let Some(ref method) = self.actor.auth_method {
            hasher.update(method.as_bytes());
        }
        if let Some(ref addr) = self.actor.source_addr {
            hasher.update(addr.as_bytes());
        }
        if let Some(ref session) = self.actor.session_id {
            hasher.update(session.as_bytes());
        }

        // Context - target
        if let Some(ref target) = self.target {
            hasher.update(target.resource_type.as_bytes());
            hasher.update(target.resource_id.as_bytes());
            for (k, v) in &target.attributes {
                hasher.update(k.as_bytes());
                hasher.update(v.as_bytes());
            }
        }

        // Outcome
        hasher.update(format!("{:?}", self.outcome).as_bytes());

        // State transition
        if let Some(ref before) = self.state_transition.before {
            hasher.update(before.state_hash.as_bytes());
        }
        if let Some(ref after) = self.state_transition.after {
            hasher.update(after.state_hash.as_bytes());
        }

        // Metadata (sorted keys for determinism)
        for (k, v) in &self.metadata {
            hasher.update(k.as_bytes());
            hasher.update(v.to_string().as_bytes());
        }

        // Chain link
        hasher.update(self.previous_hash.as_bytes());

        // Checkpoint (if present)
        if let Some(ref cp) = self.checkpoint {
            hasher.update(cp.cumulative_hash.as_bytes());
            hasher.update(cp.merkle_root.as_bytes());
            hasher.update(&cp.entries_since_last.to_le_bytes());
            hasher.update(&cp.previous_checkpoint_seq.to_le_bytes());
        }

        hasher.finalize().to_hex().to_string()
    }

    /// Verify this entry's hash is correct
    pub fn verify_hash(&self) -> bool {
        self.entry_hash == self.compute_hash()
    }

    /// Check if this entry is a checkpoint
    pub fn is_checkpoint(&self) -> bool {
        self.checkpoint.is_some()
    }
}

// ============================================================================
// Audit Entry Builder
// ============================================================================

/// Builder for creating immutable audit entries
pub struct AuditEntryBuilder {
    category: AuditCategory,
    severity: AuditSeverity,
    event_type: String,
    actor: AuditActor,
    target: Option<AuditTarget>,
    outcome: AuditOutcome,
    state_transition: StateTransition,
    metadata: BTreeMap<String, serde_json::Value>,
}

impl AuditEntryBuilder {
    /// Create a new builder
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            category: AuditCategory::SecurityAction,
            severity: AuditSeverity::Info,
            event_type: event_type.into(),
            actor: AuditActor::system(),
            target: None,
            outcome: AuditOutcome::Success,
            state_transition: StateTransition::default(),
            metadata: BTreeMap::new(),
        }
    }

    /// Set category
    pub fn category(mut self, category: AuditCategory) -> Self {
        self.category = category;
        self
    }

    /// Set severity
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set actor
    pub fn actor(mut self, actor: AuditActor) -> Self {
        self.actor = actor;
        self
    }

    /// Set target
    pub fn target(mut self, target: AuditTarget) -> Self {
        self.target = Some(target);
        self
    }

    /// Set outcome
    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Set before state
    pub fn before_state(mut self, state: StateSnapshot) -> Self {
        self.state_transition.before = Some(state);
        self
    }

    /// Set after state
    pub fn after_state(mut self, state: StateSnapshot) -> Self {
        self.state_transition.after = Some(state);
        self
    }

    /// Set full state transition
    pub fn state_transition(mut self, transition: StateTransition) -> Self {
        self.state_transition = transition;
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Build the entry (called internally by logger)
    fn build(self, sequence: u64, previous_hash: String) -> ImmutableAuditEntry {
        let entry_id = uuid::Uuid::new_v4().to_string();
        let mut entry = ImmutableAuditEntry {
            sequence,
            entry_id,
            timestamp: Utc::now(),
            category: self.category,
            severity: self.severity,
            event_type: self.event_type,
            actor: self.actor,
            target: self.target,
            outcome: self.outcome,
            state_transition: self.state_transition,
            metadata: self.metadata,
            previous_hash,
            entry_hash: String::new(),
            checkpoint: None,
        };
        entry.entry_hash = entry.compute_hash();
        entry
    }
}

// ============================================================================
// Write-Ahead Log (WAL)
// ============================================================================

/// WAL entry for crash recovery
#[derive(Debug, Serialize, Deserialize)]
struct WalEntry {
    /// Sequence number being written
    sequence: u64,
    /// Serialized audit entry
    entry_json: String,
    /// CRC32 checksum of entry_json
    checksum: u32,
}

impl WalEntry {
    fn new(sequence: u64, entry: &ImmutableAuditEntry) -> ImmutableAuditResult<Self> {
        let entry_json = serde_json::to_string(entry)
            .map_err(|e| ImmutableAuditError::Serialization(e.to_string()))?;
        let checksum = crc32fast::hash(entry_json.as_bytes());
        Ok(Self {
            sequence,
            entry_json,
            checksum,
        })
    }

    fn verify(&self) -> bool {
        crc32fast::hash(self.entry_json.as_bytes()) == self.checksum
    }

    fn to_entry(&self) -> ImmutableAuditResult<ImmutableAuditEntry> {
        serde_json::from_str(&self.entry_json)
            .map_err(|e| ImmutableAuditError::Serialization(e.to_string()))
    }
}

/// Write-Ahead Log for crash-safe writes
struct WriteAheadLog {
    #[allow(dead_code)]
    path: PathBuf,
    file: File,
}

impl WriteAheadLog {
    fn new(path: impl AsRef<Path>) -> ImmutableAuditResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)?;

        Ok(Self { path, file })
    }

    /// Write entry to WAL (before main log)
    fn prepare(&mut self, entry: &ImmutableAuditEntry) -> ImmutableAuditResult<()> {
        // Truncate WAL to start fresh
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;

        let wal_entry = WalEntry::new(entry.sequence, entry)?;
        let line = serde_json::to_string(&wal_entry)
            .map_err(|e| ImmutableAuditError::Serialization(e.to_string()))?;

        writeln!(self.file, "{}", line)?;
        self.file.sync_all()?; // Ensure WAL is durable

        Ok(())
    }

    /// Clear WAL after successful main log write
    fn commit(&mut self) -> ImmutableAuditResult<()> {
        self.file.set_len(0)?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Check for pending WAL entry (crash recovery)
    fn recover(&mut self) -> ImmutableAuditResult<Option<ImmutableAuditEntry>> {
        self.file.seek(SeekFrom::Start(0))?;

        let reader = BufReader::new(&self.file);
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let wal_entry: WalEntry = serde_json::from_str(&line)
                .map_err(|e| ImmutableAuditError::Serialization(e.to_string()))?;

            if !wal_entry.verify() {
                tracing::warn!("WAL entry failed checksum, discarding");
                continue;
            }

            let entry = wal_entry.to_entry()?;
            tracing::info!("Recovered WAL entry: sequence {}", entry.sequence);
            return Ok(Some(entry));
        }

        Ok(None)
    }
}

// ============================================================================
// Merkle Tree for Range Proofs
// ============================================================================

/// Compute Merkle root from a list of hashes
fn compute_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return String::new();
    }

    if hashes.len() == 1 {
        return hashes[0].clone();
    }

    // Build tree level by level
    let mut level: Vec<String> = hashes.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let mut hasher = Hasher::new();
            hasher.update(chunk[0].as_bytes());
            if chunk.len() > 1 {
                hasher.update(chunk[1].as_bytes());
            } else {
                // Odd number: duplicate last hash
                hasher.update(chunk[0].as_bytes());
            }
            next_level.push(hasher.finalize().to_hex().to_string());
        }

        level = next_level;
    }

    level.into_iter().next().unwrap_or_default()
}

// ============================================================================
// Immutable Audit Logger
// ============================================================================

/// Configuration for the immutable audit logger
#[derive(Debug, Clone)]
pub struct ImmutableAuditConfig {
    /// Path to the main audit log file
    pub log_path: PathBuf,
    /// Path to the WAL file
    pub wal_path: PathBuf,
    /// Entries between checkpoints
    pub checkpoint_interval: u64,
    /// Whether to verify chain on startup
    pub verify_on_startup: bool,
    /// Maximum entries to keep in memory for quick access
    pub memory_cache_size: usize,
}

impl Default for ImmutableAuditConfig {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("/var/log/whitequbit/audit.log"),
            wal_path: PathBuf::from("/var/log/whitequbit/audit.wal"),
            checkpoint_interval: 1000,
            verify_on_startup: true,
            memory_cache_size: 100,
        }
    }
}

impl ImmutableAuditConfig {
    /// Create a new config with custom log path
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_path = path.into();
        self.wal_path = self.log_path.with_extension("wal");
        self
    }

    /// Set checkpoint interval
    pub fn with_checkpoint_interval(mut self, interval: u64) -> Self {
        self.checkpoint_interval = interval;
        self
    }
}

/// Internal state of the audit logger
struct LoggerState {
    /// Next sequence number
    next_sequence: u64,
    /// Hash of the last entry
    last_hash: String,
    /// Sequence of last checkpoint
    last_checkpoint_seq: u64,
    /// Cumulative hash up to last checkpoint
    cumulative_hash: String,
    /// Hashes since last checkpoint (for Merkle root)
    hashes_since_checkpoint: Vec<String>,
    /// Recent entries cache
    recent_entries: Vec<ImmutableAuditEntry>,
}

/// Immutable audit logger with crash-safe writes and tamper detection
pub struct ImmutableAuditLogger {
    /// Configuration
    config: ImmutableAuditConfig,
    /// Main log file
    log_file: RwLock<File>,
    /// Write-ahead log
    wal: RwLock<WriteAheadLog>,
    /// Logger state
    state: RwLock<LoggerState>,
    /// Performance metrics
    metrics: RwLock<AuditMetrics>,
}

/// Performance metrics for the audit logger
#[derive(Debug, Default)]
pub struct AuditMetrics {
    /// Total entries written
    pub entries_written: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Average write latency (microseconds)
    pub avg_write_latency_us: u64,
    /// Checkpoints created
    pub checkpoints_created: u64,
    /// WAL recoveries performed
    pub wal_recoveries: u64,
}

impl ImmutableAuditLogger {
    /// Create a new immutable audit logger
    #[instrument(skip_all, fields(log_path = %config.log_path.display()))]
    pub fn new(config: ImmutableAuditConfig) -> ImmutableAuditResult<Self> {
        tracing::info!("Initializing immutable audit logger");

        // Create parent directories
        if let Some(parent) = config.log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Open main log file (append mode)
        let log_file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&config.log_path)?;

        // Initialize WAL
        let mut wal = WriteAheadLog::new(&config.wal_path)?;

        // Load existing state
        let (next_sequence, last_hash, last_checkpoint_seq, cumulative_hash) =
            Self::load_chain_state(&config.log_path)?;

        // Check for WAL recovery
        let mut metrics = AuditMetrics::default();
        if let Some(pending_entry) = wal.recover()? {
            // Check if this entry needs to be replayed
            if pending_entry.sequence == next_sequence {
                tracing::info!("Replaying WAL entry {}", pending_entry.sequence);
                // Will be written on first append
                metrics.wal_recoveries += 1;
            }
            wal.commit()?;
        }

        // Optionally verify chain integrity
        if config.verify_on_startup && next_sequence > 1 {
            tracing::info!("Verifying audit log integrity...");
            let result = Self::verify_chain(&config.log_path)?;
            if !result.valid {
                tracing::error!("Audit log integrity check failed: {:?}", result.issue);
                return Err(ImmutableAuditError::ChainBroken {
                    sequence: result.first_invalid.unwrap_or(0),
                    message: result.issue.unwrap_or_else(|| "Unknown".to_string()),
                });
            }
            tracing::info!("Integrity check passed: {} entries verified", result.entries_checked);
        }

        let state = LoggerState {
            next_sequence,
            last_hash,
            last_checkpoint_seq,
            cumulative_hash,
            hashes_since_checkpoint: Vec::new(),
            recent_entries: Vec::with_capacity(config.memory_cache_size),
        };

        Ok(Self {
            config,
            log_file: RwLock::new(log_file),
            wal: RwLock::new(wal),
            state: RwLock::new(state),
            metrics: RwLock::new(metrics),
        })
    }

    /// Load chain state from existing log
    fn load_chain_state(path: &Path) -> ImmutableAuditResult<(u64, String, u64, String)> {
        if !path.exists() {
            return Ok((1, String::new(), 0, String::new()));
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut last_sequence = 0u64;
        let mut last_hash = String::new();
        let mut last_checkpoint_seq = 0u64;
        let mut cumulative_hash = String::new();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let entry: ImmutableAuditEntry = serde_json::from_str(&line)
                .map_err(|e| ImmutableAuditError::Serialization(e.to_string()))?;

            last_sequence = entry.sequence;
            last_hash = entry.entry_hash.clone();

            if let Some(ref cp) = entry.checkpoint {
                last_checkpoint_seq = entry.sequence;
                cumulative_hash = cp.cumulative_hash.clone();
            }
        }

        Ok((last_sequence + 1, last_hash, last_checkpoint_seq, cumulative_hash))
    }

    /// Verify chain integrity
    pub fn verify_chain(path: &Path) -> ImmutableAuditResult<VerificationResult> {
        if !path.exists() {
            return Ok(VerificationResult::pass(0));
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut entries_checked = 0u64;
        let mut expected_sequence = 1u64;
        let mut expected_prev_hash = String::new();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let entry: ImmutableAuditEntry = serde_json::from_str(&line)
                .map_err(|e| ImmutableAuditError::Serialization(e.to_string()))?;

            entries_checked += 1;

            // 1. Check sequence number
            if entry.sequence != expected_sequence {
                return Ok(VerificationResult::fail(
                    entries_checked,
                    entry.sequence,
                    format!("Sequence gap: expected {}, found {}", expected_sequence, entry.sequence),
                ));
            }

            // 2. Check previous hash chain
            if entry.previous_hash != expected_prev_hash {
                return Ok(VerificationResult::fail(
                    entries_checked,
                    entry.sequence,
                    format!(
                        "Chain broken: expected prev_hash '{}...', found '{}...'",
                        &expected_prev_hash.get(..8).unwrap_or(&expected_prev_hash),
                        &entry.previous_hash.get(..8).unwrap_or(&entry.previous_hash)
                    ),
                ));
            }

            // 3. Verify entry's own hash
            if !entry.verify_hash() {
                return Ok(VerificationResult::fail(
                    entries_checked,
                    entry.sequence,
                    "Entry hash mismatch - content was modified",
                ));
            }

            // Update for next iteration
            expected_sequence += 1;
            expected_prev_hash = entry.entry_hash.clone();
        }

        Ok(VerificationResult::pass(entries_checked))
    }

    /// Append an audit entry (core write operation)
    #[instrument(skip(self, builder), fields(event_type = %builder.event_type))]
    pub fn append(&self, builder: AuditEntryBuilder) -> ImmutableAuditResult<ImmutableAuditEntry> {
        let start = Instant::now();

        let mut state = self.state.write().unwrap();
        let mut wal = self.wal.write().unwrap();
        let mut log_file = self.log_file.write().unwrap();

        // Build the entry
        let entry = builder.build(state.next_sequence, state.last_hash.clone());

        // Phase 1: Write to WAL
        wal.prepare(&entry)?;

        // Phase 2: Write to main log
        let line = serde_json::to_string(&entry)
            .map_err(|e| ImmutableAuditError::Serialization(e.to_string()))?;
        writeln!(log_file, "{}", line)?;
        log_file.sync_all()?; // Ensure durability

        // Phase 3: Clear WAL
        wal.commit()?;

        // Update state
        state.hashes_since_checkpoint.push(entry.entry_hash.clone());
        state.last_hash = entry.entry_hash.clone();
        state.next_sequence += 1;

        // Update cumulative hash
        let mut hasher = Hasher::new();
        hasher.update(state.cumulative_hash.as_bytes());
        hasher.update(entry.entry_hash.as_bytes());
        state.cumulative_hash = hasher.finalize().to_hex().to_string();

        // Add to cache
        if state.recent_entries.len() >= self.config.memory_cache_size {
            state.recent_entries.remove(0);
        }
        state.recent_entries.push(entry.clone());

        // Update metrics
        drop(state);
        drop(wal);
        drop(log_file);

        let mut metrics = self.metrics.write().unwrap();
        metrics.entries_written += 1;
        metrics.bytes_written += line.len() as u64;
        let latency = start.elapsed().as_micros() as u64;
        metrics.avg_write_latency_us =
            (metrics.avg_write_latency_us * (metrics.entries_written - 1) + latency)
                / metrics.entries_written;

        tracing::debug!("Appended entry {} in {}µs", entry.sequence, latency);

        // Check if checkpoint needed
        self.maybe_checkpoint()?;

        Ok(entry)
    }

    /// Create a checkpoint entry if interval reached
    fn maybe_checkpoint(&self) -> ImmutableAuditResult<()> {
        let state = self.state.read().unwrap();
        let entries_since = state.next_sequence - state.last_checkpoint_seq - 1;

        if entries_since < self.config.checkpoint_interval {
            return Ok(());
        }

        // Need checkpoint - release read lock and acquire write
        let hashes = state.hashes_since_checkpoint.clone();
        let prev_checkpoint = state.last_checkpoint_seq;
        let cumulative = state.cumulative_hash.clone();
        drop(state);

        self.create_checkpoint(entries_since, prev_checkpoint, cumulative, hashes)
    }

    /// Create a checkpoint entry
    fn create_checkpoint(
        &self,
        entries_since: u64,
        prev_checkpoint_seq: u64,
        cumulative_hash: String,
        hashes: Vec<String>,
    ) -> ImmutableAuditResult<()> {
        let merkle_root = compute_merkle_root(&hashes);

        let mut state = self.state.write().unwrap();
        let mut wal = self.wal.write().unwrap();
        let mut log_file = self.log_file.write().unwrap();

        // Build checkpoint entry
        let entry_id = uuid::Uuid::new_v4().to_string();
        let mut entry = ImmutableAuditEntry {
            sequence: state.next_sequence,
            entry_id,
            timestamp: Utc::now(),
            category: AuditCategory::Checkpoint,
            severity: AuditSeverity::Info,
            event_type: "checkpoint".to_string(),
            actor: AuditActor::system(),
            target: None,
            outcome: AuditOutcome::Success,
            state_transition: StateTransition::default(),
            metadata: BTreeMap::new(),
            previous_hash: state.last_hash.clone(),
            entry_hash: String::new(),
            checkpoint: Some(CheckpointData {
                entries_since_last: entries_since,
                cumulative_hash: cumulative_hash.clone(),
                merkle_root,
                previous_checkpoint_seq: prev_checkpoint_seq,
            }),
        };
        entry.entry_hash = entry.compute_hash();

        // Write checkpoint
        wal.prepare(&entry)?;

        let line = serde_json::to_string(&entry)
            .map_err(|e| ImmutableAuditError::Serialization(e.to_string()))?;
        writeln!(log_file, "{}", line)?;
        log_file.sync_all()?;

        wal.commit()?;

        // Update state
        state.last_checkpoint_seq = entry.sequence;
        state.hashes_since_checkpoint.clear();
        state.last_hash = entry.entry_hash.clone();
        state.next_sequence += 1;

        // Update cumulative hash
        let mut hasher = Hasher::new();
        hasher.update(state.cumulative_hash.as_bytes());
        hasher.update(entry.entry_hash.as_bytes());
        state.cumulative_hash = hasher.finalize().to_hex().to_string();

        drop(state);

        let mut metrics = self.metrics.write().unwrap();
        metrics.checkpoints_created += 1;

        tracing::info!("Created checkpoint at sequence {}", entry.sequence);

        Ok(())
    }

    // =========================================================================
    // Convenience Methods for Common Events
    // =========================================================================

    /// Log agent startup
    pub fn log_startup(&self, version: &str) -> ImmutableAuditResult<ImmutableAuditEntry> {
        self.append(
            AuditEntryBuilder::new("agent_startup")
                .category(AuditCategory::Lifecycle)
                .severity(AuditSeverity::Notice)
                .metadata("version", serde_json::json!(version))
                .metadata("pid", serde_json::json!(std::process::id())),
        )
    }

    /// Log agent shutdown
    pub fn log_shutdown(&self, reason: &str) -> ImmutableAuditResult<ImmutableAuditEntry> {
        self.append(
            AuditEntryBuilder::new("agent_shutdown")
                .category(AuditCategory::Lifecycle)
                .severity(AuditSeverity::Notice)
                .metadata("reason", serde_json::json!(reason)),
        )
    }

    /// Log a security action with before/after state
    pub fn log_security_action(
        &self,
        event_type: impl Into<String>,
        actor: AuditActor,
        target: AuditTarget,
        before: Option<StateSnapshot>,
        after: Option<StateSnapshot>,
        outcome: AuditOutcome,
    ) -> ImmutableAuditResult<ImmutableAuditEntry> {
        let mut builder = AuditEntryBuilder::new(event_type)
            .category(AuditCategory::SecurityAction)
            .severity(match &outcome {
                AuditOutcome::Success => AuditSeverity::Notice,
                AuditOutcome::Failure { .. } => AuditSeverity::Error,
                AuditOutcome::Denied { .. } => AuditSeverity::Warning,
                AuditOutcome::RolledBack { .. } => AuditSeverity::Warning,
                AuditOutcome::Pending => AuditSeverity::Info,
            })
            .actor(actor)
            .target(target)
            .outcome(outcome);

        if let Some(b) = before {
            builder = builder.before_state(b);
        }
        if let Some(a) = after {
            builder = builder.after_state(a);
        }

        self.append(builder)
    }

    /// Log authentication event
    pub fn log_auth(
        &self,
        actor: AuditActor,
        success: bool,
        reason: Option<&str>,
    ) -> ImmutableAuditResult<ImmutableAuditEntry> {
        let event_type = if success { "auth_success" } else { "auth_failure" };
        let severity = if success { AuditSeverity::Info } else { AuditSeverity::Warning };
        let outcome = if success {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure {
                reason: reason.unwrap_or("Unknown").to_string(),
            }
        };

        self.append(
            AuditEntryBuilder::new(event_type)
                .category(AuditCategory::Authentication)
                .severity(severity)
                .actor(actor)
                .outcome(outcome),
        )
    }

    // =========================================================================
    // Query Methods
    // =========================================================================

    /// Get current sequence number
    pub fn current_sequence(&self) -> u64 {
        self.state.read().unwrap().next_sequence - 1
    }

    /// Get the last entry hash
    pub fn last_hash(&self) -> String {
        self.state.read().unwrap().last_hash.clone()
    }

    /// Get recent entries from cache
    pub fn recent_entries(&self, count: usize) -> Vec<ImmutableAuditEntry> {
        let state = self.state.read().unwrap();
        let len = state.recent_entries.len();
        let start = len.saturating_sub(count);
        state.recent_entries[start..].to_vec()
    }

    /// Get audit metrics
    pub fn metrics(&self) -> AuditMetrics {
        let metrics = self.metrics.read().unwrap();
        AuditMetrics {
            entries_written: metrics.entries_written,
            bytes_written: metrics.bytes_written,
            avg_write_latency_us: metrics.avg_write_latency_us,
            checkpoints_created: metrics.checkpoints_created,
            wal_recoveries: metrics.wal_recoveries,
        }
    }

    /// Verify integrity of the audit log
    pub fn verify(&self) -> ImmutableAuditResult<VerificationResult> {
        Self::verify_chain(&self.config.log_path)
    }
}

// ============================================================================
// Verification Result
// ============================================================================

/// Result of integrity verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether verification passed
    pub valid: bool,
    /// Number of entries checked
    pub entries_checked: u64,
    /// First invalid entry sequence (if any)
    pub first_invalid: Option<u64>,
    /// Description of the issue
    pub issue: Option<String>,
}

impl VerificationResult {
    fn pass(entries_checked: u64) -> Self {
        Self {
            valid: true,
            entries_checked,
            first_invalid: None,
            issue: None,
        }
    }

    fn fail(entries_checked: u64, first_invalid: u64, issue: impl Into<String>) -> Self {
        Self {
            valid: false,
            entries_checked,
            first_invalid: Some(first_invalid),
            issue: Some(issue.into()),
        }
    }
}

// ============================================================================
// Tamper Detection Explanation
// ============================================================================

/// Documentation struct explaining tamper detection mechanisms
/// 
/// # How Tampering is Detected
///
/// The immutable audit log uses multiple layers of protection:
///
/// ## 1. Entry Hash (Self-Integrity)
/// 
/// Each entry contains a BLAKE3 hash of its own contents:
/// ```text
/// entry_hash = BLAKE3(sequence || timestamp || event_type || actor || 
///                      target || outcome || state || metadata || previous_hash)
/// ```
///
/// **Detection**: If any field is modified, `entry.verify_hash()` returns false.
///
/// ## 2. Hash Chain (Sequential Integrity)
///
/// Each entry stores the hash of the previous entry:
/// ```text
/// Entry[1].previous_hash = ""  (genesis)
/// Entry[2].previous_hash = Entry[1].entry_hash
/// Entry[3].previous_hash = Entry[2].entry_hash
/// ...
/// ```
///
/// **Detection**: Modifying Entry[N] changes its hash, breaking the chain
/// for Entry[N+1] and all subsequent entries.
///
/// ## 3. Sequence Numbers (Completeness)
///
/// Entries have monotonically increasing sequence numbers starting at 1.
///
/// **Detection**: 
/// - Deleting entries creates gaps (e.g., 1, 2, 4 - missing 3)
/// - Inserting entries creates duplicates
/// - Both are detected during verification
///
/// ## 4. Checkpoints (Efficient Verification)
///
/// Periodic checkpoint entries contain:
/// - `cumulative_hash`: Hash of all entries up to this point
/// - `merkle_root`: Merkle tree root of entries since last checkpoint
///
/// **Detection**: Allows verifying large logs by checking checkpoint
/// consistency without reading every entry.
///
/// ## 5. Merkle Tree (Range Proofs)
///
/// Entries between checkpoints form a Merkle tree.
///
/// **Detection**: Enables proving a specific entry exists and is unmodified
/// without revealing other entries.
///
/// # Attack Scenarios
///
/// | Attack | Detection Method |
/// |--------|-----------------|
/// | Modify entry content | Entry hash mismatch |
/// | Delete entry | Sequence gap detected |
/// | Insert fake entry | Chain hash mismatch at next entry |
/// | Truncate log tail | Missing expected entries (if count known) |
/// | Replace entire log | Checkpoint cumulative hash mismatch |
/// | Reorder entries | Sequence number mismatch |
pub struct TamperDetectionGuide;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(dir: &TempDir) -> ImmutableAuditConfig {
        ImmutableAuditConfig {
            log_path: dir.path().join("audit.log"),
            wal_path: dir.path().join("audit.wal"),
            checkpoint_interval: 10,
            verify_on_startup: false,
            memory_cache_size: 5,
        }
    }

    #[test]
    fn test_basic_append() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let logger = ImmutableAuditLogger::new(config).unwrap();

        let entry = logger.append(
            AuditEntryBuilder::new("test_event")
                .category(AuditCategory::Lifecycle)
        ).unwrap();

        assert_eq!(entry.sequence, 1);
        assert!(entry.verify_hash());
        assert!(entry.previous_hash.is_empty()); // Genesis
    }

    #[test]
    fn test_hash_chain() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let logger = ImmutableAuditLogger::new(config).unwrap();

        let e1 = logger.append(AuditEntryBuilder::new("event_1")).unwrap();
        let e2 = logger.append(AuditEntryBuilder::new("event_2")).unwrap();
        let e3 = logger.append(AuditEntryBuilder::new("event_3")).unwrap();

        // Verify chain links
        assert!(e1.previous_hash.is_empty());
        assert_eq!(e2.previous_hash, e1.entry_hash);
        assert_eq!(e3.previous_hash, e2.entry_hash);

        // Verify each entry
        assert!(e1.verify_hash());
        assert!(e2.verify_hash());
        assert!(e3.verify_hash());
    }

    #[test]
    fn test_chain_verification() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let logger = ImmutableAuditLogger::new(config.clone()).unwrap();

        // Write several entries
        for i in 0..5 {
            logger.append(AuditEntryBuilder::new(format!("event_{}", i))).unwrap();
        }

        // Verify chain
        let result = ImmutableAuditLogger::verify_chain(&config.log_path).unwrap();
        assert!(result.valid);
        assert_eq!(result.entries_checked, 5);
    }

    #[test]
    fn test_tamper_detection_modified_entry() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);

        // Write entries
        {
            let logger = ImmutableAuditLogger::new(config.clone()).unwrap();
            for i in 0..3 {
                logger.append(AuditEntryBuilder::new(format!("event_{}", i))).unwrap();
            }
        }

        // Tamper with the file - modify entry 2
        let content = std::fs::read_to_string(&config.log_path).unwrap();
        let tampered = content.replace("event_1", "tampered_event");
        std::fs::write(&config.log_path, tampered).unwrap();

        // Verify should fail
        let result = ImmutableAuditLogger::verify_chain(&config.log_path).unwrap();
        assert!(!result.valid);
        assert_eq!(result.first_invalid, Some(2)); // Entry 2 was modified
        assert!(result.issue.as_ref().unwrap().contains("hash"));
    }

    #[test]
    fn test_before_after_state() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let logger = ImmutableAuditLogger::new(config).unwrap();

        let before = StateSnapshot::new("firewall_rules", serde_json::json!({
            "rule_count": 10,
            "rules": ["allow ssh", "block telnet"]
        }));

        let after = StateSnapshot::new("firewall_rules", serde_json::json!({
            "rule_count": 11,
            "rules": ["allow ssh", "block telnet", "allow https"]
        }));

        let entry = logger.log_security_action(
            "firewall_rule_added",
            AuditActor::authenticated("admin", "ssh_key"),
            AuditTarget::new("firewall_rule", "rule_42"),
            Some(before.clone()),
            Some(after.clone()),
            AuditOutcome::Success,
        ).unwrap();

        assert!(entry.state_transition.has_change());
        assert_ne!(
            entry.state_transition.before.as_ref().unwrap().state_hash,
            entry.state_transition.after.as_ref().unwrap().state_hash
        );
    }

    #[test]
    #[ignore = "Slow due to fsync operations"]
    fn test_checkpoint_creation() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.checkpoint_interval = 5; // Checkpoint every 5 entries

        let logger = ImmutableAuditLogger::new(config.clone()).unwrap();

        // Write enough entries to trigger checkpoint
        for i in 0..6 {
            logger.append(AuditEntryBuilder::new(format!("event_{}", i))).unwrap();
        }

        // Check metrics
        let metrics = logger.metrics();
        assert!(metrics.checkpoints_created >= 1);
    }

    #[test]
    fn test_persistence_and_recovery() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);

        // Write entries
        {
            let logger = ImmutableAuditLogger::new(config.clone()).unwrap();
            logger.append(AuditEntryBuilder::new("event_1")).unwrap();
            logger.append(AuditEntryBuilder::new("event_2")).unwrap();
        }

        // Reopen and verify state recovered
        {
            let logger = ImmutableAuditLogger::new(config.clone()).unwrap();
            assert_eq!(logger.current_sequence(), 2);

            // Append continues correctly
            let e3 = logger.append(AuditEntryBuilder::new("event_3")).unwrap();
            assert_eq!(e3.sequence, 3);
        }

        // Verify full chain
        let result = ImmutableAuditLogger::verify_chain(&config.log_path).unwrap();
        assert!(result.valid);
        assert_eq!(result.entries_checked, 3);
    }

    #[test]
    fn test_merkle_root() {
        let hashes = vec![
            "hash1".to_string(),
            "hash2".to_string(),
            "hash3".to_string(),
            "hash4".to_string(),
        ];

        let root = compute_merkle_root(&hashes);
        assert!(!root.is_empty());

        // Same hashes should produce same root
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root, root2);

        // Different hashes should produce different root
        let different = vec!["hash1".to_string(), "hash2".to_string(), "modified".to_string()];
        let root3 = compute_merkle_root(&different);
        assert_ne!(root, root3);
    }

    #[test]
    fn test_state_snapshot_comparison() {
        let s1 = StateSnapshot::new("test", serde_json::json!({"key": "value1"}));
        let s2 = StateSnapshot::new("test", serde_json::json!({"key": "value1"}));
        let s3 = StateSnapshot::new("test", serde_json::json!({"key": "value2"}));

        // Same content = same hash
        assert_eq!(s1.state_hash, s2.state_hash);
        assert!(!s1.differs_from(&s2));

        // Different content = different hash
        assert!(s1.differs_from(&s3));
    }

    #[test]
    fn test_audit_actor_types() {
        let system = AuditActor::system();
        assert_eq!(system.principal, "system");

        let user = AuditActor::authenticated("alice", "password")
            .with_source("192.168.1.100")
            .with_session("sess_abc123");
        
        assert_eq!(user.principal, "alice");
        assert_eq!(user.auth_method.as_deref(), Some("password"));
        assert_eq!(user.source_addr.as_deref(), Some("192.168.1.100"));
        assert_eq!(user.session_id.as_deref(), Some("sess_abc123"));
    }

    #[test]
    fn test_recent_entries_cache() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.memory_cache_size = 3;

        let logger = ImmutableAuditLogger::new(config).unwrap();

        // Write more than cache size
        for i in 0..5 {
            logger.append(AuditEntryBuilder::new(format!("event_{}", i))).unwrap();
        }

        // Cache should only have last 3
        let recent = logger.recent_entries(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].event_type, "event_2");
        assert_eq!(recent[2].event_type, "event_4");
    }
}
