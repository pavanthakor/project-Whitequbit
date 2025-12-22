//! Deterministic Security Versioning System
//!
//! Provides a robust versioning system for tracking security state changes:
//!
//! - **Deterministic**: Same security state → same version hash
//! - **Monotonic**: Version sequence always increases
//! - **Persistent**: Survives restarts via WAL
//! - **Observable**: Changes trigger downstream notifications
//! - **Auditable**: Complete version history preserved
//!
//! # Version Structure
//!
//! ```text
//! SecurityVersion {
//!     sequence: 42,                          // Monotonic counter
//!     hash: "a1b2c3d4...",                  // BLAKE3 content hash
//!     timestamp: "2025-12-22T10:30:00Z",    // When version was created
//!     parent_hash: Some("z9y8x7w6..."),     // Previous version hash
//! }
//! ```
//!
//! # Hash Computation
//!
//! ```text
//! version_hash = BLAKE3(
//!     sequence.to_le_bytes() ||
//!     timestamp_millis.to_le_bytes() ||
//!     parent_hash.as_bytes() ||
//!     content_hash.as_bytes()
//! )
//! ```

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors from versioning operations
#[derive(Error, Debug)]
pub enum VersioningError {
    /// Version not found
    #[error("Version not found: {0}")]
    VersionNotFound(String),

    /// Invalid version format
    #[error("Invalid version format: {0}")]
    InvalidFormat(String),

    /// Version already exists
    #[error("Version already exists: {0}")]
    VersionExists(String),

    /// Persistence error
    #[error("Persistence error: {0}")]
    PersistenceError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Chain integrity violation
    #[error("Chain integrity violation: expected parent {expected}, got {actual}")]
    ChainIntegrityViolation {
        /// Expected parent hash
        expected: String,
        /// Actual parent hash
        actual: String,
    },

    /// Subscriber error
    #[error("Subscriber notification failed: {0}")]
    SubscriberError(String),
}

/// Result type for versioning operations
pub type VersioningResult<T> = Result<T, VersioningError>;

// ============================================================================
// Security Version
// ============================================================================

/// A unique identifier for a security state version
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VersionHash(String);

impl VersionHash {
    /// Create a new version hash from a string
    pub fn new(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    /// Get the hash as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this is the genesis (initial) version
    pub fn is_genesis(&self) -> bool {
        self.0 == GENESIS_HASH
    }

    /// Get the short form (first 8 chars)
    pub fn short(&self) -> &str {
        &self.0[..8.min(self.0.len())]
    }
}

impl std::fmt::Display for VersionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for VersionHash {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for VersionHash {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Genesis hash for the initial version
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A complete security version record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVersion {
    /// Monotonically increasing sequence number
    pub sequence: u64,

    /// Content-based hash of the security state
    pub content_hash: VersionHash,

    /// Unique version identifier (hash of this record)
    pub version_hash: VersionHash,

    /// Parent version hash (for chain integrity)
    pub parent_hash: VersionHash,

    /// When this version was created
    pub timestamp: DateTime<Utc>,

    /// Unix timestamp in milliseconds (for deterministic hashing)
    pub timestamp_ms: u64,

    /// Human-readable description of what changed
    pub change_summary: String,

    /// Category of change
    pub change_type: VersionChangeType,

    /// Optional metadata
    #[serde(default)]
    pub metadata: VersionMetadata,
}

impl SecurityVersion {
    /// Create a new version
    pub fn new(
        sequence: u64,
        content_hash: VersionHash,
        parent_hash: VersionHash,
        change_summary: impl Into<String>,
        change_type: VersionChangeType,
    ) -> Self {
        let timestamp = Utc::now();
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut version = Self {
            sequence,
            content_hash,
            version_hash: VersionHash::new(""), // Computed below
            parent_hash,
            timestamp,
            timestamp_ms,
            change_summary: change_summary.into(),
            change_type,
            metadata: VersionMetadata::default(),
        };

        version.version_hash = version.compute_version_hash();
        version
    }

    /// Create the genesis (initial) version
    pub fn genesis(content_hash: VersionHash) -> Self {
        Self::new(
            0,
            content_hash,
            VersionHash::new(GENESIS_HASH),
            "Initial security state",
            VersionChangeType::Initial,
        )
    }

    /// Compute the version hash from components
    fn compute_version_hash(&self) -> VersionHash {
        use blake3::Hasher;

        let mut hasher = Hasher::new();

        // Include all deterministic fields
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.timestamp_ms.to_le_bytes());
        hasher.update(self.parent_hash.as_str().as_bytes());
        hasher.update(self.content_hash.as_str().as_bytes());
        hasher.update(self.change_summary.as_bytes());
        hasher.update(&[self.change_type as u8]);

        let hash = hasher.finalize();
        VersionHash::new(hash.to_hex().as_str()[..32].to_string())
    }

    /// Verify the version hash is correct
    pub fn verify(&self) -> bool {
        let computed = self.compute_version_hash();
        computed == self.version_hash
    }

    /// Check if this version follows another
    pub fn follows(&self, other: &SecurityVersion) -> bool {
        self.parent_hash == other.version_hash && self.sequence == other.sequence + 1
    }

    /// Get age since creation
    pub fn age(&self) -> Duration {
        let now = Utc::now();
        (now - self.timestamp).to_std().unwrap_or(Duration::ZERO)
    }
}

/// Type of version change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum VersionChangeType {
    /// Initial version (genesis)
    Initial = 0,
    /// Firewall rule added
    FirewallRuleAdded = 1,
    /// Firewall rule removed
    FirewallRuleRemoved = 2,
    /// Firewall rule modified
    FirewallRuleModified = 3,
    /// Port opened
    PortOpened = 4,
    /// Port closed
    PortClosed = 5,
    /// Service started
    ServiceStarted = 6,
    /// Service stopped
    ServiceStopped = 7,
    /// Auth configuration changed
    AuthConfigChanged = 8,
    /// Security posture improved
    PostureImproved = 9,
    /// Security posture degraded
    PostureDegraded = 10,
    /// Manual intervention
    ManualChange = 11,
    /// Rollback executed
    Rollback = 12,
    /// Recovery from crash
    Recovery = 13,
    /// Periodic snapshot
    PeriodicSnapshot = 14,
    /// Unknown change
    Unknown = 255,
}

impl std::fmt::Display for VersionChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => write!(f, "initial"),
            Self::FirewallRuleAdded => write!(f, "firewall_rule_added"),
            Self::FirewallRuleRemoved => write!(f, "firewall_rule_removed"),
            Self::FirewallRuleModified => write!(f, "firewall_rule_modified"),
            Self::PortOpened => write!(f, "port_opened"),
            Self::PortClosed => write!(f, "port_closed"),
            Self::ServiceStarted => write!(f, "service_started"),
            Self::ServiceStopped => write!(f, "service_stopped"),
            Self::AuthConfigChanged => write!(f, "auth_config_changed"),
            Self::PostureImproved => write!(f, "posture_improved"),
            Self::PostureDegraded => write!(f, "posture_degraded"),
            Self::ManualChange => write!(f, "manual_change"),
            Self::Rollback => write!(f, "rollback"),
            Self::Recovery => write!(f, "recovery"),
            Self::PeriodicSnapshot => write!(f, "periodic_snapshot"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Additional metadata for a version
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionMetadata {
    /// Security score at this version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_score: Option<u8>,

    /// Action ID that caused this version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,

    /// Operator who made the change
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,

    /// Affected rules/ports/services
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_resources: Vec<String>,

    /// Rollback target (if this is a rollback)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_target: Option<String>,
}

// ============================================================================
// Version History
// ============================================================================

/// In-memory version history with bounded size
pub struct VersionHistory {
    /// Maximum versions to keep in memory
    max_size: usize,

    /// Versions in order (oldest first)
    versions: VecDeque<SecurityVersion>,

    /// Index by version hash
    by_hash: std::collections::HashMap<VersionHash, usize>,

    /// Index by sequence number
    by_sequence: std::collections::BTreeMap<u64, VersionHash>,
}

impl VersionHistory {
    /// Create a new history with max size
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            versions: VecDeque::with_capacity(max_size),
            by_hash: std::collections::HashMap::new(),
            by_sequence: std::collections::BTreeMap::new(),
        }
    }

    /// Add a version to history
    pub fn push(&mut self, version: SecurityVersion) {
        let hash = version.version_hash.clone();
        let sequence = version.sequence;

        // Evict oldest if at capacity
        if self.versions.len() >= self.max_size {
            if let Some(old) = self.versions.pop_front() {
                self.by_hash.remove(&old.version_hash);
                self.by_sequence.remove(&old.sequence);
            }
        }

        let index = self.versions.len();
        self.versions.push_back(version);
        self.by_hash.insert(hash, index);
        self.by_sequence.insert(sequence, self.versions.back().unwrap().version_hash.clone());
    }

    /// Get version by hash
    pub fn get(&self, hash: &VersionHash) -> Option<&SecurityVersion> {
        self.by_hash.get(hash).and_then(|&idx| self.versions.get(idx))
    }

    /// Get version by sequence number
    pub fn get_by_sequence(&self, sequence: u64) -> Option<&SecurityVersion> {
        self.by_sequence
            .get(&sequence)
            .and_then(|hash| self.get(hash))
    }

    /// Get the latest version
    pub fn latest(&self) -> Option<&SecurityVersion> {
        self.versions.back()
    }

    /// Get versions in a range (inclusive)
    pub fn range(&self, start_seq: u64, end_seq: u64) -> Vec<&SecurityVersion> {
        self.by_sequence
            .range(start_seq..=end_seq)
            .filter_map(|(_, hash)| self.get(hash))
            .collect()
    }

    /// Get count of versions
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Get all versions (oldest first)
    pub fn all(&self) -> impl Iterator<Item = &SecurityVersion> {
        self.versions.iter()
    }

    /// Verify chain integrity
    pub fn verify_chain(&self) -> bool {
        let versions: Vec<_> = self.versions.iter().collect();
        
        for window in versions.windows(2) {
            if let [prev, curr] = window {
                if !curr.follows(prev) {
                    return false;
                }
            }
        }
        
        true
    }
}

// ============================================================================
// Version Store (Persistence)
// ============================================================================

/// Journal operation for version persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum VersionJournalOp {
    /// New version created
    VersionCreated { version: SecurityVersion },
    /// Checkpoint marker
    Checkpoint { 
        latest_sequence: u64,
        latest_hash: String,
        total_versions: u64,
    },
}

/// Persistent version store
pub struct VersionStore {
    /// Path to journal file
    journal_path: PathBuf,

    /// Next sequence number
    next_sequence: AtomicU64,

    /// In-memory history
    history: RwLock<VersionHistory>,

    /// Whether to fsync after writes
    sync_writes: bool,

    /// Total versions ever created
    total_versions: AtomicU64,
}

impl VersionStore {
    /// Create or open a version store
    pub fn new(path: impl AsRef<Path>, history_size: usize) -> VersioningResult<Self> {
        let journal_path = path.as_ref().to_path_buf();

        // Create parent directory
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let store = Self {
            journal_path,
            next_sequence: AtomicU64::new(0),
            history: RwLock::new(VersionHistory::new(history_size)),
            sync_writes: true,
            total_versions: AtomicU64::new(0),
        };

        // Load existing versions
        store.recover()?;

        Ok(store)
    }

    /// Recover state from journal
    fn recover(&self) -> VersioningResult<()> {
        use std::io::{BufRead, BufReader};

        if !self.journal_path.exists() {
            info!("No version journal found, starting fresh");
            return Ok(());
        }

        let file = std::fs::File::open(&self.journal_path)?;
        let reader = BufReader::new(file);

        let mut history = self.history.write().unwrap();
        let mut max_sequence = 0u64;
        let mut count = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            match serde_json::from_str::<VersionJournalOp>(&line) {
                Ok(VersionJournalOp::VersionCreated { version }) => {
                    max_sequence = max_sequence.max(version.sequence);
                    history.push(version);
                    count += 1;
                }
                Ok(VersionJournalOp::Checkpoint { latest_sequence, .. }) => {
                    max_sequence = max_sequence.max(latest_sequence);
                }
                Err(e) => {
                    warn!(?e, "Skipping malformed journal entry");
                }
            }
        }

        self.next_sequence.store(max_sequence + 1, Ordering::SeqCst);
        self.total_versions.store(count, Ordering::SeqCst);

        info!(
            versions = count,
            latest_sequence = max_sequence,
            "Recovered version history"
        );

        Ok(())
    }

    /// Write operation to journal
    fn write_op(&self, op: &VersionJournalOp) -> VersioningResult<()> {
        use std::io::Write;

        let mut line = serde_json::to_string(op)
            .map_err(|e| VersioningError::SerializationError(e.to_string()))?;
        line.push('\n');

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)?;

        file.write_all(line.as_bytes())?;

        if self.sync_writes {
            file.sync_all()?;
        }

        Ok(())
    }

    /// Create a new version
    #[instrument(skip(self))]
    pub fn create_version(
        &self,
        content_hash: VersionHash,
        change_summary: impl Into<String> + std::fmt::Debug,
        change_type: VersionChangeType,
        metadata: Option<VersionMetadata>,
    ) -> VersioningResult<SecurityVersion> {
        let sequence = self.next_sequence.fetch_add(1, Ordering::SeqCst);

        // Get parent hash
        let parent_hash = {
            let history = self.history.read().unwrap();
            history
                .latest()
                .map(|v| v.version_hash.clone())
                .unwrap_or_else(|| VersionHash::new(GENESIS_HASH))
        };

        // Check for duplicate content (no-op if same)
        {
            let history = self.history.read().unwrap();
            if let Some(latest) = history.latest() {
                if latest.content_hash == content_hash {
                    debug!("Content unchanged, not creating new version");
                    return Ok(latest.clone());
                }
            }
        }

        let mut version = SecurityVersion::new(
            sequence,
            content_hash,
            parent_hash,
            change_summary,
            change_type,
        );

        if let Some(meta) = metadata {
            version.metadata = meta;
        }

        // Persist first
        self.write_op(&VersionJournalOp::VersionCreated {
            version: version.clone(),
        })?;

        // Then add to in-memory history
        {
            let mut history = self.history.write().unwrap();
            history.push(version.clone());
        }

        self.total_versions.fetch_add(1, Ordering::SeqCst);

        info!(
            sequence = version.sequence,
            hash = %version.version_hash.short(),
            change_type = %version.change_type,
            "Created new security version"
        );

        Ok(version)
    }

    /// Get the current (latest) version
    pub fn current(&self) -> Option<SecurityVersion> {
        let history = self.history.read().unwrap();
        history.latest().cloned()
    }

    /// Get version by hash
    pub fn get(&self, hash: &VersionHash) -> Option<SecurityVersion> {
        let history = self.history.read().unwrap();
        history.get(hash).cloned()
    }

    /// Get version by sequence
    pub fn get_by_sequence(&self, sequence: u64) -> Option<SecurityVersion> {
        let history = self.history.read().unwrap();
        history.get_by_sequence(sequence).cloned()
    }

    /// Get versions in a range
    pub fn get_range(&self, start: u64, end: u64) -> Vec<SecurityVersion> {
        let history = self.history.read().unwrap();
        history.range(start, end).into_iter().cloned().collect()
    }

    /// Get total version count
    pub fn total_versions(&self) -> u64 {
        self.total_versions.load(Ordering::SeqCst)
    }

    /// Get next sequence number
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence.load(Ordering::SeqCst)
    }

    /// Write a checkpoint
    pub fn checkpoint(&self) -> VersioningResult<()> {
        let history = self.history.read().unwrap();
        
        if let Some(latest) = history.latest() {
            self.write_op(&VersionJournalOp::Checkpoint {
                latest_sequence: latest.sequence,
                latest_hash: latest.version_hash.to_string(),
                total_versions: self.total_versions.load(Ordering::SeqCst),
            })?;
        }

        Ok(())
    }

    /// Verify chain integrity
    pub fn verify_integrity(&self) -> bool {
        let history = self.history.read().unwrap();
        
        // Verify hash chain
        if !history.verify_chain() {
            return false;
        }

        // Verify each version's internal hash
        for version in history.all() {
            if !version.verify() {
                return false;
            }
        }

        true
    }
}

// ============================================================================
// Version Change Notification
// ============================================================================

/// A version change event
#[derive(Debug, Clone)]
pub struct VersionChangeEvent {
    /// The new version
    pub version: SecurityVersion,
    /// The previous version (if any)
    pub previous: Option<SecurityVersion>,
    /// Whether this is the first version
    pub is_initial: bool,
    /// Security score delta (if available)
    pub score_delta: Option<i16>,
}

/// Subscriber for version changes
pub trait VersionSubscriber: Send + Sync {
    /// Called when a new version is created
    fn on_version_change(&self, event: &VersionChangeEvent) -> VersioningResult<()>;

    /// Subscriber name for logging
    fn name(&self) -> &str;
}

/// Registry for version change subscribers
pub struct VersionNotifier {
    /// Registered subscribers
    subscribers: RwLock<Vec<Arc<dyn VersionSubscriber>>>,
}

impl VersionNotifier {
    /// Create a new notifier
    pub fn new() -> Self {
        Self {
            subscribers: RwLock::new(Vec::new()),
        }
    }

    /// Register a subscriber
    pub fn subscribe(&self, subscriber: Arc<dyn VersionSubscriber>) {
        let mut subs = self.subscribers.write().unwrap();
        subs.push(subscriber);
    }

    /// Notify all subscribers of a version change
    pub fn notify(&self, event: &VersionChangeEvent) -> VersioningResult<()> {
        let subs = self.subscribers.read().unwrap();
        let mut errors = Vec::new();

        for sub in subs.iter() {
            if let Err(e) = sub.on_version_change(event) {
                warn!(
                    subscriber = sub.name(),
                    error = %e,
                    "Subscriber notification failed"
                );
                errors.push((sub.name().to_string(), e));
            }
        }

        if !errors.is_empty() {
            return Err(VersioningError::SubscriberError(format!(
                "{} subscribers failed",
                errors.len()
            )));
        }

        Ok(())
    }

    /// Get subscriber count
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.read().unwrap().len()
    }
}

impl Default for VersionNotifier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Version Manager
// ============================================================================

/// Configuration for the version manager
#[derive(Debug, Clone)]
pub struct VersionManagerConfig {
    /// Path to version journal
    pub journal_path: PathBuf,
    /// Maximum versions to keep in memory
    pub history_size: usize,
    /// Whether to fsync after writes
    pub sync_writes: bool,
    /// Minimum interval between versions (deduplication)
    pub min_interval: Duration,
}

impl Default for VersionManagerConfig {
    fn default() -> Self {
        Self {
            journal_path: PathBuf::from("/var/lib/whitequbit/versions.log"),
            history_size: 1000,
            sync_writes: true,
            min_interval: Duration::from_secs(1),
        }
    }
}

/// The main version manager
pub struct VersionManager {
    /// Version store
    store: VersionStore,
    /// Change notifier
    notifier: VersionNotifier,
    /// Configuration
    config: VersionManagerConfig,
    /// Last version timestamp (for rate limiting)
    last_version_time: RwLock<Option<std::time::Instant>>,
}

impl VersionManager {
    /// Create a new version manager
    pub fn new(config: VersionManagerConfig) -> VersioningResult<Self> {
        let store = VersionStore::new(&config.journal_path, config.history_size)?;

        Ok(Self {
            store,
            notifier: VersionNotifier::new(),
            config,
            last_version_time: RwLock::new(None),
        })
    }

    /// Subscribe to version changes
    pub fn subscribe(&self, subscriber: Arc<dyn VersionSubscriber>) {
        self.notifier.subscribe(subscriber);
    }

    /// Record a security state change
    #[instrument(skip(self, content_hash, metadata))]
    pub fn record_change(
        &self,
        content_hash: impl Into<VersionHash>,
        change_summary: impl Into<String> + std::fmt::Debug,
        change_type: VersionChangeType,
        metadata: Option<VersionMetadata>,
    ) -> VersioningResult<SecurityVersion> {
        let content_hash = content_hash.into();
        
        // Rate limiting
        {
            let last = self.last_version_time.read().unwrap();
            if let Some(last_time) = *last {
                if last_time.elapsed() < self.config.min_interval {
                    debug!("Version rate limited, skipping");
                    if let Some(current) = self.store.current() {
                        return Ok(current);
                    }
                }
            }
        }

        // Get previous version for event
        let previous = self.store.current();

        // Create new version
        let version = self.store.create_version(
            content_hash,
            change_summary,
            change_type,
            metadata.clone(),
        )?;

        // Check if actually new (might be deduplicated)
        let is_new = previous
            .as_ref()
            .map(|p| p.version_hash != version.version_hash)
            .unwrap_or(true);

        if is_new {
            // Update rate limit timestamp
            {
                let mut last = self.last_version_time.write().unwrap();
                *last = Some(std::time::Instant::now());
            }

            // Compute score delta if available
            let score_delta = metadata.as_ref().and_then(|m| {
                m.security_score.and_then(|new_score| {
                    previous.as_ref().and_then(|p| {
                        p.metadata.security_score.map(|old_score| {
                            new_score as i16 - old_score as i16
                        })
                    })
                })
            });

            // Notify subscribers
            let event = VersionChangeEvent {
                version: version.clone(),
                previous,
                is_initial: version.sequence == 0,
                score_delta,
            };

            if let Err(e) = self.notifier.notify(&event) {
                warn!(?e, "Some subscribers failed notification");
            }
        }

        Ok(version)
    }

    /// Get the current version
    pub fn current(&self) -> Option<SecurityVersion> {
        self.store.current()
    }

    /// Get version by hash
    pub fn get(&self, hash: impl Into<VersionHash>) -> Option<SecurityVersion> {
        self.store.get(&hash.into())
    }

    /// Get version by sequence
    pub fn get_by_sequence(&self, sequence: u64) -> Option<SecurityVersion> {
        self.store.get_by_sequence(sequence)
    }

    /// Get version history
    pub fn history(&self, count: usize) -> Vec<SecurityVersion> {
        let current_seq = self.store.next_sequence();
        let start = current_seq.saturating_sub(count as u64);
        self.store.get_range(start, current_seq)
    }

    /// Compare two versions
    pub fn compare(&self, v1: &VersionHash, v2: &VersionHash) -> Option<VersionComparison> {
        let version1 = self.store.get(v1)?;
        let version2 = self.store.get(v2)?;

        Some(VersionComparison {
            older: if version1.sequence < version2.sequence {
                version1.clone()
            } else {
                version2.clone()
            },
            newer: if version1.sequence >= version2.sequence {
                version1.clone()
            } else {
                version2.clone()
            },
            sequence_delta: (version1.sequence as i64 - version2.sequence as i64).unsigned_abs(),
            time_delta: version1.timestamp - version2.timestamp,
            same_content: version1.content_hash == version2.content_hash,
        })
    }

    /// Verify chain integrity
    pub fn verify_integrity(&self) -> bool {
        self.store.verify_integrity()
    }

    /// Get statistics
    pub fn stats(&self) -> VersionStats {
        VersionStats {
            total_versions: self.store.total_versions(),
            current_sequence: self.store.next_sequence().saturating_sub(1),
            history_size: self.config.history_size,
            subscriber_count: self.notifier.subscriber_count(),
            integrity_valid: self.verify_integrity(),
        }
    }
}

/// Comparison between two versions
#[derive(Debug, Clone)]
pub struct VersionComparison {
    /// The older version
    pub older: SecurityVersion,
    /// The newer version
    pub newer: SecurityVersion,
    /// Difference in sequence numbers
    pub sequence_delta: u64,
    /// Time between versions
    pub time_delta: chrono::Duration,
    /// Whether content hash is the same
    pub same_content: bool,
}

/// Version manager statistics
#[derive(Debug, Clone, Serialize)]
pub struct VersionStats {
    /// Total versions ever created
    pub total_versions: u64,
    /// Current sequence number
    pub current_sequence: u64,
    /// In-memory history size limit
    pub history_size: usize,
    /// Number of registered subscribers
    pub subscriber_count: usize,
    /// Whether chain integrity is valid
    pub integrity_valid: bool,
}

// ============================================================================
// Built-in Subscribers
// ============================================================================

/// Subscriber that logs version changes
pub struct LoggingSubscriber {
    /// Minimum change type to log
    pub min_level: VersionChangeType,
}

impl LoggingSubscriber {
    /// Create a new logging subscriber
    pub fn new() -> Self {
        Self {
            min_level: VersionChangeType::Initial,
        }
    }
}

impl Default for LoggingSubscriber {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionSubscriber for LoggingSubscriber {
    fn on_version_change(&self, event: &VersionChangeEvent) -> VersioningResult<()> {
        info!(
            sequence = event.version.sequence,
            hash = %event.version.version_hash.short(),
            change_type = %event.version.change_type,
            summary = %event.version.change_summary,
            score_delta = ?event.score_delta,
            "Security version changed"
        );
        Ok(())
    }

    fn name(&self) -> &str {
        "logging"
    }
}

/// Subscriber that writes version changes to a file
pub struct FileSubscriber {
    path: PathBuf,
}

impl FileSubscriber {
    /// Create a new file subscriber
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl VersionSubscriber for FileSubscriber {
    fn on_version_change(&self, event: &VersionChangeEvent) -> VersioningResult<()> {
        use std::io::Write;

        let line = serde_json::to_string(&event.version)
            .map_err(|e| VersioningError::SerializationError(e.to_string()))?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        writeln!(file, "{}", line)?;
        file.sync_all()?;

        Ok(())
    }

    fn name(&self) -> &str {
        "file"
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_version_hash_creation() {
        let hash = VersionHash::new("abc123");
        assert_eq!(hash.as_str(), "abc123");
        assert_eq!(hash.short(), "abc123");
    }

    #[test]
    fn test_security_version_creation() {
        let version = SecurityVersion::new(
            1,
            VersionHash::new("content123"),
            VersionHash::new(GENESIS_HASH),
            "Test change",
            VersionChangeType::FirewallRuleAdded,
        );

        assert_eq!(version.sequence, 1);
        assert!(!version.version_hash.as_str().is_empty());
        assert!(version.verify());
    }

    #[test]
    fn test_version_genesis() {
        let genesis = SecurityVersion::genesis(VersionHash::new("initial_content"));

        assert_eq!(genesis.sequence, 0);
        assert!(genesis.parent_hash.is_genesis());
        assert_eq!(genesis.change_type, VersionChangeType::Initial);
    }

    #[test]
    fn test_version_chain() {
        let v1 = SecurityVersion::genesis(VersionHash::new("content1"));
        
        let v2 = SecurityVersion::new(
            1,
            VersionHash::new("content2"),
            v1.version_hash.clone(),
            "Change 1",
            VersionChangeType::PortOpened,
        );

        assert!(v2.follows(&v1));
        assert!(!v1.follows(&v2));
    }

    #[test]
    fn test_version_history() {
        let mut history = VersionHistory::new(3);

        for i in 0..5 {
            let version = SecurityVersion::new(
                i,
                VersionHash::new(format!("content{}", i)),
                if i == 0 {
                    VersionHash::new(GENESIS_HASH)
                } else {
                    history.latest().unwrap().version_hash.clone()
                },
                format!("Change {}", i),
                VersionChangeType::PeriodicSnapshot,
            );
            history.push(version);
        }

        // Should only keep last 3
        assert_eq!(history.len(), 3);
        assert!(history.get_by_sequence(0).is_none());
        assert!(history.get_by_sequence(2).is_some());
        assert!(history.get_by_sequence(4).is_some());
    }

    #[test]
    fn test_version_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("versions.log");

        let store = VersionStore::new(&path, 100).unwrap();

        let v1 = store
            .create_version(
                VersionHash::new("content1"),
                "First change",
                VersionChangeType::Initial,
                None,
            )
            .unwrap();

        assert_eq!(v1.sequence, 0);

        let v2 = store
            .create_version(
                VersionHash::new("content2"),
                "Second change",
                VersionChangeType::FirewallRuleAdded,
                None,
            )
            .unwrap();

        assert_eq!(v2.sequence, 1);
        assert!(v2.follows(&v1));

        // Current should be v2
        let current = store.current().unwrap();
        assert_eq!(current.sequence, 1);
    }

    #[test]
    fn test_version_store_deduplication() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("versions.log");

        let store = VersionStore::new(&path, 100).unwrap();

        let v1 = store
            .create_version(
                VersionHash::new("same_content"),
                "First change",
                VersionChangeType::Initial,
                None,
            )
            .unwrap();

        // Same content should return existing version
        let v2 = store
            .create_version(
                VersionHash::new("same_content"),
                "Second change",
                VersionChangeType::PeriodicSnapshot,
                None,
            )
            .unwrap();

        assert_eq!(v1.version_hash, v2.version_hash);
        assert_eq!(store.total_versions(), 1);
    }

    #[test]
    fn test_version_store_recovery() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("versions.log");

        // Create some versions
        {
            let store = VersionStore::new(&path, 100).unwrap();

            store
                .create_version(
                    VersionHash::new("content1"),
                    "Change 1",
                    VersionChangeType::Initial,
                    None,
                )
                .unwrap();

            store
                .create_version(
                    VersionHash::new("content2"),
                    "Change 2",
                    VersionChangeType::FirewallRuleAdded,
                    None,
                )
                .unwrap();

            store
                .create_version(
                    VersionHash::new("content3"),
                    "Change 3",
                    VersionChangeType::ServiceStarted,
                    None,
                )
                .unwrap();
        }

        // Recover from journal
        let store = VersionStore::new(&path, 100).unwrap();

        assert_eq!(store.total_versions(), 3);
        assert_eq!(store.next_sequence(), 3);

        let current = store.current().unwrap();
        assert_eq!(current.sequence, 2);
    }

    #[test]
    fn test_version_notifier() {
        use std::sync::atomic::AtomicUsize;

        struct CountingSubscriber {
            count: AtomicUsize,
        }

        impl VersionSubscriber for CountingSubscriber {
            fn on_version_change(&self, _event: &VersionChangeEvent) -> VersioningResult<()> {
                self.count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn name(&self) -> &str {
                "counter"
            }
        }

        let notifier = VersionNotifier::new();
        let subscriber = Arc::new(CountingSubscriber {
            count: AtomicUsize::new(0),
        });

        notifier.subscribe(subscriber.clone());

        let event = VersionChangeEvent {
            version: SecurityVersion::genesis(VersionHash::new("test")),
            previous: None,
            is_initial: true,
            score_delta: None,
        };

        notifier.notify(&event).unwrap();
        notifier.notify(&event).unwrap();

        assert_eq!(subscriber.count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_version_integrity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("versions.log");

        let store = VersionStore::new(&path, 100).unwrap();

        for i in 0..10 {
            store
                .create_version(
                    VersionHash::new(format!("content{}", i)),
                    format!("Change {}", i),
                    VersionChangeType::PeriodicSnapshot,
                    None,
                )
                .unwrap();
        }

        assert!(store.verify_integrity());
    }
}
