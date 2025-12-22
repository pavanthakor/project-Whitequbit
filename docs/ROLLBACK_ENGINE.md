# Rollback Engine Design

## Overview

The Rollback Engine provides a correctness-first approach to undoing system-level security actions. It tracks every firewall rule applied by the agent and ensures they can be safely rolled back without affecting unrelated rules.

## Key Properties

1. **Complete Tracking**: Every firewall rule is associated with action ID, timestamp, and version
2. **Automatic Rollback**: Failed actions trigger automatic rollback of changes
3. **Manual Rollback**: Operators can manually rollback specific actions or time ranges
4. **Rule Isolation**: Rollback only removes rules created by this agent
5. **Idempotency**: Multiple rollback attempts produce the same result

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Rollback Engine                                   │
│                                                                             │
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────────────────┐  │
│  │ ActionTracker  │──▶│ RuleRegistry   │──▶│ FirewallRuleRecord         │  │
│  │                │   │ (by action_id) │   │ - rule_id                  │  │
│  └────────────────┘   └────────────────┘   │ - action_id                │  │
│         │                    │              │ - timestamp                │  │
│         ▼                    ▼              │ - version                  │  │
│  ┌────────────────┐   ┌────────────────┐   │ - spec                     │  │
│  │ RollbackJournal│   │ TTL Coordinator│   │ - state                    │  │
│  │ (WAL on disk)  │   │                │   └────────────────────────────┘  │
│  └────────────────┘   └────────────────┘                                    │
│         │                                                                   │
│         ▼                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      RollbackExecutor                                │   │
│  │  - Acquire coordination lock                                         │   │
│  │  - Verify rule ownership                                             │   │
│  │  - Execute removal via FirewallBackend                               │   │
│  │  - Mark journal entry complete                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Structures

### FirewallRuleRecord

Complete record of an applied firewall rule:

```rust
/// Complete record of a firewall rule applied by this agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleRecord {
    /// Unique rule identifier (from FirewallBackend)
    pub rule_id: RuleId,
    
    /// Action that created this rule
    pub action_id: ActionId,
    
    /// Journal entry for this rule's action
    pub journal_entry_id: JournalEntryId,
    
    /// When the rule was created (Unix timestamp ms)
    pub created_at_ms: u64,
    
    /// Monotonic version number (for ordering)
    pub version: u64,
    
    /// The complete rule specification (for verification)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        let mut record = Self {
            rule_id,
            action_id,
            journal_entry_id,
            created_at_ms: now_ms,
            version,
            spec: spec.clone(),
            state: RuleRecordState::Active,
            expires_at_ms: spec.ttl.map(|ttl| now_ms + ttl.as_millis() as u64),
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
}
```

### RuleRegistry

In-memory registry with multiple indexes for efficient queries:

```rust
/// In-memory registry of all firewall rules created by this agent
pub struct RuleRegistry {
    /// Primary index: rule_id → record
    by_rule_id: HashMap<RuleId, FirewallRuleRecord>,
    
    /// Index by action: action_id → Vec<rule_id>
    by_action_id: HashMap<ActionId, Vec<RuleId>>,
    
    /// Index by journal entry: journal_entry_id → Vec<rule_id>
    by_journal_entry: HashMap<JournalEntryId, Vec<RuleId>>,
    
    /// Time-ordered index: (version, rule_id) for ordering
    by_version: BTreeMap<u64, RuleId>,
    
    /// Global version counter (monotonic)
    next_version: AtomicU64,
    
    /// Registry version for change detection
    registry_version: AtomicU64,
}

impl RuleRegistry {
    /// Register a new rule
    pub fn register(&mut self, record: FirewallRuleRecord) -> Result<(), RollbackError>;
    
    /// Get a rule by ID
    pub fn get(&self, rule_id: &RuleId) -> Option<&FirewallRuleRecord>;
    
    /// Get all rules for an action
    pub fn get_by_action(&self, action_id: &ActionId) -> Vec<&FirewallRuleRecord>;
    
    /// Get all rules for a journal entry
    pub fn get_by_journal_entry(&self, entry_id: JournalEntryId) -> Vec<&FirewallRuleRecord>;
    
    /// Get rules in version order (for LIFO rollback)
    pub fn get_by_version_desc(&self) -> Vec<&FirewallRuleRecord>;
    
    /// Get rules created in a time range
    pub fn get_by_time_range(&self, start_ms: u64, end_ms: u64) -> Vec<&FirewallRuleRecord>;
    
    /// Update rule state
    pub fn update_state(&mut self, rule_id: &RuleId, state: RuleRecordState) -> Result<(), RollbackError>;
    
    /// Remove a rule record (after successful rollback)
    pub fn remove(&mut self, rule_id: &RuleId) -> Option<FirewallRuleRecord>;
    
    /// Check if a rule exists and is active
    pub fn is_active(&self, rule_id: &RuleId) -> bool;
    
    /// Get count of active rules
    pub fn active_count(&self) -> usize;
}
```

### RollbackJournal

Enhanced WAL specifically for rollback operations:

```rust
/// Write-ahead log for rollback tracking
pub struct RollbackJournal {
    /// Path to journal file
    path: PathBuf,
    
    /// In-memory records
    records: Arc<RwLock<HashMap<RuleId, FirewallRuleRecord>>>,
    
    /// Next sequence number
    next_seq: AtomicU64,
    
    /// Fsync after writes
    sync_writes: bool,
}

/// Journal operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RollbackJournalOp {
    /// Rule was created
    RuleCreated {
        record: FirewallRuleRecord,
    },
    /// Rule state changed
    StateChanged {
        rule_id: RuleId,
        old_state: RuleRecordState,
        new_state: RuleRecordState,
        generation: u64,
    },
    /// Rule was removed
    RuleRemoved {
        rule_id: RuleId,
        reason: RemovalReason,
    },
    /// Rollback started
    RollbackStarted {
        rollback_id: RollbackId,
        scope: RollbackScope,
        rule_ids: Vec<RuleId>,
    },
    /// Rollback completed
    RollbackCompleted {
        rollback_id: RollbackId,
        success: bool,
        failed_rules: Vec<RuleId>,
    },
    /// Checkpoint marker
    Checkpoint {
        up_to_seq: u64,
        active_rules: Vec<RuleId>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
```

### RollbackScope

Defines what to rollback:

```rust
/// Scope of a rollback operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackScope {
    /// Rollback a single action
    SingleAction {
        action_id: ActionId,
    },
    /// Rollback a journal entry
    JournalEntry {
        entry_id: JournalEntryId,
    },
    /// Rollback specific rules by ID
    SpecificRules {
        rule_ids: Vec<RuleId>,
    },
    /// Rollback last N rules (by version)
    LastN {
        count: usize,
    },
    /// Rollback rules in time range
    TimeRange {
        start_ms: u64,
        end_ms: u64,
    },
    /// Rollback all rules (emergency)
    All,
}

/// Unique identifier for a rollback operation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RollbackId(String);

impl RollbackId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}
```

## Core Algorithm

### Rule Creation Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Rule Creation Flow                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Action executor receives firewall action                                │
│                                                                             │
│  2. Journal.prepare(action_id, action_data, compensation_data)              │
│     → Returns journal_entry_id                                              │
│     → Persisted to WAL before continuing                                    │
│                                                                             │
│  3. FirewallBackend.add_rule(spec)                                          │
│     → Returns rule_id                                                       │
│                                                                             │
│  4. On success:                                                             │
│     a. Create FirewallRuleRecord                                            │
│     b. RollbackJournal.log_rule_created(record)                             │
│        → Persisted to rollback journal                                      │
│     c. RuleRegistry.register(record)                                        │
│        → In-memory index updated                                            │
│     d. Journal.commit(journal_entry_id)                                     │
│        → Action marked complete                                             │
│                                                                             │
│  5. On failure:                                                             │
│     a. Trigger automatic rollback                                           │
│     b. RecoveryManager.recover()                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Rollback Execution

```rust
/// Execute a rollback operation
pub async fn execute_rollback(&self, scope: RollbackScope) -> RollbackResult {
    let rollback_id = RollbackId::generate();
    
    info!(%rollback_id, ?scope, "Starting rollback");
    
    // 1. Determine which rules to rollback
    let rules = self.resolve_scope(&scope)?;
    
    if rules.is_empty() {
        return Ok(RollbackResult::empty(rollback_id));
    }
    
    // 2. Log rollback start (for crash recovery)
    self.journal.log_rollback_started(
        rollback_id.clone(),
        scope.clone(),
        rules.iter().map(|r| r.rule_id.clone()).collect(),
    ).await?;
    
    // 3. Sort rules by version descending (LIFO order)
    let mut rules = rules;
    rules.sort_by(|a, b| b.version.cmp(&a.version));
    
    // 4. Execute rollback for each rule
    let mut results = Vec::new();
    let mut failed_rules = Vec::new();
    
    for record in &rules {
        match self.rollback_single_rule(record).await {
            Ok(result) => {
                results.push(result);
            }
            Err(e) => {
                warn!(rule_id = %record.rule_id, error = %e, "Rollback failed");
                failed_rules.push(record.rule_id.clone());
                results.push(RuleRollbackResult::failure(record.rule_id.clone(), e));
            }
        }
    }
    
    // 5. Log rollback complete
    let success = failed_rules.is_empty();
    self.journal.log_rollback_completed(
        rollback_id.clone(),
        success,
        failed_rules.clone(),
    ).await?;
    
    // 6. Return result
    Ok(RollbackResult {
        rollback_id,
        scope,
        total_rules: rules.len(),
        succeeded: results.iter().filter(|r| r.success).count(),
        failed: failed_rules.len(),
        results,
        requires_intervention: !failed_rules.is_empty(),
    })
}
```

### Single Rule Rollback

```rust
/// Rollback a single rule
async fn rollback_single_rule(&self, record: &FirewallRuleRecord) -> Result<RuleRollbackResult, RollbackError> {
    let rule_id = &record.rule_id;
    
    // 1. Acquire coordination lock (prevents race with TTL)
    let _guard = match self.coordinator.try_acquire_rollback_removal(rule_id) {
        Ok(()) => RollbackGuard::new(self.coordinator.clone(), rule_id.clone()),
        Err(CoordinationError::TtlInProgress) => {
            // TTL is already removing this rule, skip
            debug!(%rule_id, "TTL already removing rule, skipping");
            return Ok(RuleRollbackResult::skipped(rule_id.clone(), "TTL in progress"));
        }
        Err(CoordinationError::AlreadyRemoved) => {
            // Rule already removed
            self.registry.update_state(rule_id, RuleRecordState::ManuallyRemoved)?;
            return Ok(RuleRollbackResult::already_removed(rule_id.clone()));
        }
        Err(e) => {
            return Err(RollbackError::Lock(e.to_string()));
        }
    };
    
    // 2. Update state: Active → RollingBack
    self.registry.update_state(rule_id, RuleRecordState::RollingBack)?;
    self.journal.log_state_changed(
        rule_id.clone(),
        RuleRecordState::Active,
        RuleRecordState::RollingBack,
        record.generation + 1,
    ).await?;
    
    // 3. Verify rule is ours before removing
    //    The firewall backend tags rules with our prefix
    //    If rule doesn't exist or isn't ours, handle gracefully
    
    // 4. Remove via firewall backend
    let result = self.firewall.remove_rule(rule_id).await;
    
    match result {
        Ok(op_result) => {
            // 5a. Success - update state
            self.registry.update_state(rule_id, RuleRecordState::RolledBack)?;
            self.journal.log_rule_removed(rule_id.clone(), RemovalReason::RolledBack).await?;
            self.coordinator.complete_removal(rule_id);
            
            info!(%rule_id, "Rule rolled back successfully");
            Ok(RuleRollbackResult::success(rule_id.clone()))
        }
        Err(FirewallError::RuleNotFound(_)) => {
            // 5b. Rule doesn't exist - still success (idempotent)
            self.registry.update_state(rule_id, RuleRecordState::ManuallyRemoved)?;
            self.journal.log_rule_removed(rule_id.clone(), RemovalReason::ExternalRemoval).await?;
            self.coordinator.complete_removal(rule_id);
            
            info!(%rule_id, "Rule already removed (idempotent rollback)");
            Ok(RuleRollbackResult::already_removed(rule_id.clone()))
        }
        Err(e) => {
            // 5c. Failure - mark for intervention
            self.registry.update_state(rule_id, RuleRecordState::RollbackFailed)?;
            self.journal.log_state_changed(
                rule_id.clone(),
                RuleRecordState::RollingBack,
                RuleRecordState::RollbackFailed,
                record.generation + 2,
            ).await?;
            self.coordinator.release_removal(rule_id);
            
            error!(%rule_id, error = %e, "Rollback failed");
            Err(RollbackError::RecoveryFailed(format!(
                "Failed to remove rule {}: {}", rule_id, e
            )))
        }
    }
}
```

## Idempotency

Rollback operations are idempotent through:

1. **State Tracking**: Each rule has a state that prevents double-rollback
2. **Rule Not Found is Success**: If a rule doesn't exist, the rollback succeeds
3. **Generation Numbers**: CAS operations prevent stale updates
4. **Rollback IDs**: Each rollback operation has a unique ID for deduplication

```rust
/// Check if rollback is needed for a rule
fn needs_rollback(&self, record: &FirewallRuleRecord) -> bool {
    match record.state {
        RuleRecordState::Active => true,
        RuleRecordState::RollingBack => true,  // Retry interrupted rollback
        RuleRecordState::RolledBack => false,  // Already done
        RuleRecordState::RollbackFailed => true,  // Retry failed
        RuleRecordState::Expired => false,     // TTL handled it
        RuleRecordState::ManuallyRemoved => false,  // External removal
    }
}
```

## Crash Recovery

### Startup Recovery Procedure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Startup Recovery Procedure                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Load rollback journal from disk                                         │
│                                                                             │
│  2. For each record:                                                        │
│     match record.state:                                                     │
│       Active → verify_rule_exists()                                         │
│         if !exists: mark ManuallyRemoved                                    │
│         else: add to registry                                               │
│                                                                             │
│       RollingBack → rollback was interrupted                                │
│         resume_rollback(record)                                             │
│                                                                             │
│       RollbackFailed → needs manual intervention                            │
│         log_warning_for_operator()                                          │
│         add to intervention_queue                                           │
│                                                                             │
│       RolledBack | Expired | ManuallyRemoved →                              │
│         skip (terminal state)                                               │
│                                                                             │
│  3. Check for incomplete rollback operations:                               │
│     If RollbackStarted without RollbackCompleted:                           │
│       resume_rollback(rollback_id)                                          │
│                                                                             │
│  4. Sync registry with actual firewall state                                │
│     For each registered rule:                                               │
│       if !firewall.rule_exists(rule_id):                                    │
│         mark ManuallyRemoved                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Automatic Rollback

Triggered automatically on action failure:

```rust
/// Execute action with automatic rollback on failure
pub async fn execute_with_rollback<F, R>(&self, action: F) -> Result<R, ActionError>
where
    F: FnOnce() -> Pin<Box<dyn Future<Output = Result<R, ActionError>> + Send>>,
{
    let action_id = ActionId::new();
    
    // Prepare journal entry
    let entry_id = self.journal.prepare(
        action_id.clone(),
        "firewall_action",
        serde_json::json!({}),
        serde_json::json!({"action_id": action_id.to_string()}),
    ).await?;
    
    // Execute action
    match action().await {
        Ok(result) => {
            // Commit on success
            self.journal.commit(entry_id).await?;
            Ok(result)
        }
        Err(e) => {
            // Automatic rollback on failure
            warn!(action_id = %action_id, error = %e, "Action failed, initiating rollback");
            
            let scope = RollbackScope::JournalEntry { entry_id };
            if let Err(rollback_err) = self.execute_rollback(scope).await {
                error!("Automatic rollback failed: {}", rollback_err);
            }
            
            Err(e)
        }
    }
}
```

## Manual Rollback API

```rust
/// Public API for manual rollback operations
impl RollbackEngine {
    /// Rollback a specific action by ID
    pub async fn rollback_action(&self, action_id: ActionId) -> RollbackResult {
        self.execute_rollback(RollbackScope::SingleAction { action_id }).await
    }
    
    /// Rollback specific rules by ID
    pub async fn rollback_rules(&self, rule_ids: Vec<RuleId>) -> RollbackResult {
        self.execute_rollback(RollbackScope::SpecificRules { rule_ids }).await
    }
    
    /// Rollback last N rules
    pub async fn rollback_last_n(&self, count: usize) -> RollbackResult {
        self.execute_rollback(RollbackScope::LastN { count }).await
    }
    
    /// Rollback rules in time range
    pub async fn rollback_time_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> RollbackResult {
        self.execute_rollback(RollbackScope::TimeRange {
            start_ms: start.timestamp_millis() as u64,
            end_ms: end.timestamp_millis() as u64,
        }).await
    }
    
    /// Emergency: rollback all rules
    pub async fn rollback_all(&self) -> RollbackResult {
        warn!("Emergency rollback of ALL rules initiated");
        self.execute_rollback(RollbackScope::All).await
    }
    
    /// Query rules that would be affected by a rollback
    pub async fn preview_rollback(&self, scope: RollbackScope) -> Vec<FirewallRuleRecord> {
        self.resolve_scope(&scope).unwrap_or_default()
    }
    
    /// Get rules requiring manual intervention
    pub async fn get_failed_rollbacks(&self) -> Vec<FirewallRuleRecord> {
        self.registry.get_by_state(RuleRecordState::RollbackFailed)
    }
    
    /// Retry failed rollbacks
    pub async fn retry_failed(&self) -> RollbackResult {
        let failed = self.get_failed_rollbacks().await;
        let rule_ids = failed.iter().map(|r| r.rule_id.clone()).collect();
        self.execute_rollback(RollbackScope::SpecificRules { rule_ids }).await
    }
}
```

## Result Types

```rust
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
    /// Check if rollback was completely successful
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }
    
    /// Get failed rule IDs
    pub fn failed_rules(&self) -> Vec<RuleId> {
        self.results.iter()
            .filter(|r| !r.success)
            .map(|r| r.rule_id.clone())
            .collect()
    }
}

/// Result of rolling back a single rule
#[derive(Debug)]
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
```

## Safety Guarantees

### Rule Isolation

Rules are isolated through:

1. **Rule Tagging**: Every rule created by the agent has a unique comment/tag
2. **Registry Tracking**: Only rules in our registry can be rolled back
3. **Verification**: Before removal, verify the rule has our tag
4. **Firewall Backend**: The backend only removes rules with our tag

```rust
/// Verify a rule is ours before removal
async fn verify_rule_ownership(&self, rule_id: &RuleId) -> Result<bool, RollbackError> {
    // Check registry first
    if !self.registry.contains(rule_id) {
        return Ok(false);
    }
    
    // Verify in firewall (rule might have our tag)
    // The FirewallBackend.remove_rule() already checks this,
    // but we double-check for defense in depth
    match self.firewall.get_rule(rule_id).await? {
        Some(state) => {
            // Rule exists and was returned by our backend (which only returns our rules)
            Ok(true)
        }
        None => {
            // Rule doesn't exist in firewall
            Ok(false)
        }
    }
}
```

### Version Ordering

Rules are rolled back in LIFO order using version numbers:

```rust
/// Get rules for rollback in correct order
fn get_rules_in_rollback_order(&self, rule_ids: &[RuleId]) -> Vec<FirewallRuleRecord> {
    let mut records: Vec<_> = rule_ids.iter()
        .filter_map(|id| self.registry.get(id).cloned())
        .collect();
    
    // Sort by version descending (most recent first = LIFO)
    records.sort_by(|a, b| b.version.cmp(&a.version));
    
    records
}
```

## Integration with TTL Engine

The rollback engine coordinates with the TTL engine:

```rust
impl RollbackEngine {
    /// Notify that a rule was expired by TTL
    pub fn notify_ttl_expired(&self, rule_id: &RuleId) {
        if let Some(record) = self.registry.get_mut(rule_id) {
            record.state = RuleRecordState::Expired;
            record.generation += 1;
            let _ = self.journal.log_rule_removed(rule_id.clone(), RemovalReason::TtlExpired);
        }
    }
}
```

## Metrics and Observability

```rust
/// Rollback metrics for monitoring
#[derive(Debug, Default)]
pub struct RollbackMetrics {
    /// Total rollback operations
    pub total_rollbacks: AtomicU64,
    /// Successful rollbacks
    pub successful_rollbacks: AtomicU64,
    /// Failed rollbacks
    pub failed_rollbacks: AtomicU64,
    /// Total rules rolled back
    pub rules_rolled_back: AtomicU64,
    /// Rules requiring intervention
    pub rules_requiring_intervention: AtomicU64,
    /// Automatic rollbacks triggered
    pub automatic_rollbacks: AtomicU64,
    /// Manual rollbacks triggered
    pub manual_rollbacks: AtomicU64,
}
```

## Testing Strategy

1. **Unit Tests**: State transitions, registry operations, journal operations
2. **Integration Tests**: Full rollback flow with mock firewall
3. **Idempotency Tests**: Multiple rollback calls produce same result
4. **Crash Tests**: Kill at each state, verify recovery
5. **Race Tests**: Concurrent rollback and TTL expiration
6. **Isolation Tests**: Verify unrelated rules are never touched
7. **LIFO Tests**: Verify correct ordering of rollback
