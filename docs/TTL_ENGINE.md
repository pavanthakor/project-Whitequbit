# TTL Engine Design

## Overview

The TTL (Time-To-Live) Engine manages automatic expiration of temporary firewall rules. It ensures:

1. **Automatic expiration** - Rules are removed exactly when their TTL expires
2. **Crash resilience** - Expiration times survive agent restarts
3. **No busy loops** - Uses event-driven timers instead of polling
4. **Safe removal** - Expired rules removed through the same safe path as manual removal
5. **Rollback safety** - TTL operations coordinate with rollback to prevent races

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              TTL Engine                                     │
│                                                                            │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────────────────────┐  │
│  │ TtlScheduler │──▶│ TtlWheelTimer │──▶│ Expiration Event → EventLoop │  │
│  └──────────────┘   └───────────────┘   └──────────────────────────────┘  │
│         │                  │                         │                     │
│         ▼                  ▼                         ▼                     │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────────────────────┐  │
│  │ TtlRegistry  │◀──│   Persister   │   │    FirewallBackend.remove()  │  │
│  │ (in-memory)  │   │ (disk state)  │   └──────────────────────────────┘  │
│  └──────────────┘   └───────────────┘                                      │
└────────────────────────────────────────────────────────────────────────────┘
```

## Data Structures

### TtlEntry

Represents a single rule with TTL metadata:

```rust
/// A rule with time-to-live metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlEntry {
    /// The firewall rule ID
    pub rule_id: RuleId,
    
    /// Absolute expiration time (Unix timestamp milliseconds)
    /// Using absolute time survives restarts
    pub expires_at_ms: u64,
    
    /// When the rule was created (for audit/debugging)
    pub created_at_ms: u64,
    
    /// Original TTL duration (for display purposes)
    pub original_ttl_secs: u64,
    
    /// Current state of this TTL entry
    pub state: TtlState,
    
    /// Generation counter for CAS operations
    /// Prevents ABA problems with concurrent modifications
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
```

### TtlRegistry

In-memory index for fast lookups:

```rust
/// In-memory registry of all TTL entries
pub struct TtlRegistry {
    /// Primary index: rule_id → entry
    by_rule_id: HashMap<RuleId, TtlEntry>,
    
    /// Time-ordered index for efficient "next expiration" queries
    /// BTreeMap<expires_at_ms, Vec<RuleId>> 
    /// Multiple rules can expire at the same millisecond
    by_expiration: BTreeMap<u64, HashSet<RuleId>>,
    
    /// Generation counter for the entire registry
    /// Incremented on any mutation, used for change detection
    version: AtomicU64,
}

impl TtlRegistry {
    /// Get the soonest expiration time
    /// Returns None if no TTL entries exist
    pub fn next_expiration(&self) -> Option<u64>;
    
    /// Get all entries expiring at or before the given time
    pub fn entries_expiring_before(&self, deadline_ms: u64) -> Vec<TtlEntry>;
    
    /// Register a new TTL entry
    pub fn register(&mut self, entry: TtlEntry) -> Result<(), TtlError>;
    
    /// Cancel a TTL (rule removed before expiration)
    /// Returns the cancelled entry if it existed
    pub fn cancel(&mut self, rule_id: &RuleId) -> Option<TtlEntry>;
    
    /// Mark entry as expiring (state transition)
    pub fn mark_expiring(&mut self, rule_id: &RuleId) -> Result<(), TtlError>;
    
    /// Mark entry as expired (successful removal)
    pub fn mark_expired(&mut self, rule_id: &RuleId) -> Result<(), TtlError>;
    
    /// Mark entry as failed (removal failed, needs retry)
    pub fn mark_failed(&mut self, rule_id: &RuleId) -> Result<(), TtlError>;
}
```

### TtlPersister

Durable storage for crash resilience:

```rust
/// Persistent storage for TTL state
/// 
/// Uses a simple append-only log with periodic compaction.
/// Format: one JSON entry per line (JSONL)
pub struct TtlPersister {
    /// Path to the TTL state file
    path: PathBuf,
    
    /// Write-ahead log for durability
    wal: File,
    
    /// Whether to fsync after each write
    sync_writes: bool,
}

impl TtlPersister {
    /// Load all TTL entries from disk
    /// Called during agent startup
    pub fn load(&self) -> Result<Vec<TtlEntry>, TtlError>;
    
    /// Persist a new or updated entry
    /// Returns after data is durable (if sync_writes=true)
    pub fn persist(&mut self, entry: &TtlEntry) -> Result<(), TtlError>;
    
    /// Remove an entry (writes a tombstone)
    pub fn remove(&mut self, rule_id: &RuleId) -> Result<(), TtlError>;
    
    /// Compact the log file (remove old entries, tombstones)
    /// Called periodically or when file exceeds threshold
    pub fn compact(&mut self, live_entries: &[TtlEntry]) -> Result<(), TtlError>;
}

/// Persistent log entry format
#[derive(Serialize, Deserialize)]
struct TtlLogEntry {
    /// Monotonic sequence number
    seq: u64,
    /// Timestamp of this log entry
    timestamp_ms: u64,
    /// The operation
    op: TtlLogOp,
}

#[derive(Serialize, Deserialize)]
enum TtlLogOp {
    /// Register a new TTL
    Register(TtlEntry),
    /// Update entry state
    Update { rule_id: RuleId, state: TtlState, generation: u64 },
    /// Remove entry (tombstone)
    Remove { rule_id: RuleId },
    /// Compaction marker (entries before this are superseded)
    Compacted { up_to_seq: u64 },
}
```

### TtlWheelTimer

Efficient timer management without busy loops:

```rust
/// Hierarchical timing wheel for efficient TTL scheduling
/// 
/// Instead of one timer per rule, we maintain a single timer
/// for the next expiration. When it fires, we process all
/// expired rules and reschedule for the next batch.
pub struct TtlWheelTimer {
    /// Channel to receive timer ticks
    tick_rx: mpsc::Receiver<TtlTick>,
    
    /// Handle to the timer task
    timer_handle: JoinHandle<()>,
    
    /// Current scheduled wakeup (for rescheduling)
    next_wakeup: Arc<AtomicU64>,
}

/// Timer notification
pub struct TtlTick {
    /// The scheduled wakeup time that triggered this tick
    pub scheduled_at_ms: u64,
    /// Actual time when tick occurred
    pub actual_at_ms: u64,
}

impl TtlWheelTimer {
    /// Create a new timer
    pub fn new() -> (Self, mpsc::Sender<TtlTimerCommand>);
    
    /// Schedule next wakeup at the given time
    /// If already scheduled earlier, this is a no-op
    /// If scheduled later, reschedules to earlier time
    pub async fn schedule_at(&self, expires_at_ms: u64);
    
    /// Cancel current timer (for shutdown)
    pub async fn cancel(&self);
}

pub enum TtlTimerCommand {
    /// Schedule wakeup at given time
    ScheduleAt(u64),
    /// Cancel current timer
    Cancel,
    /// Shutdown the timer task
    Shutdown,
}
```

## Core Algorithm

### Timer Scheduling (No Busy Loops)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Timer Scheduling Algorithm                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. On rule add with TTL:                                           │
│     - Calculate absolute expiration time                            │
│     - Add to registry (by_expiration index)                         │
│     - If this is the soonest expiration:                            │
│         reschedule_timer(expiration_time)                           │
│                                                                     │
│  2. On timer fire:                                                  │
│     - Get all entries where expires_at <= now()                     │
│     - For each expired entry:                                       │
│         process_expiration(entry)                                   │
│     - Get next soonest expiration                                   │
│     - If exists: reschedule_timer(next_expiration)                  │
│                                                                     │
│  3. reschedule_timer(time):                                         │
│     - tokio::time::sleep_until(time)                                │
│     - Single timer, not per-rule timers                             │
│                                                                     │
│  Result: O(log n) scheduling, no polling, no busy loops             │
└─────────────────────────────────────────────────────────────────────┘
```

### Expiration Processing

```rust
/// Process expired rules
async fn process_expirations(&self, tick: TtlTick) -> Result<(), TtlError> {
    let now_ms = current_time_ms();
    
    // Get all expired entries atomically
    let expired: Vec<TtlEntry> = {
        let registry = self.registry.read();
        registry.entries_expiring_before(now_ms)
    };
    
    if expired.is_empty() {
        return Ok(());
    }
    
    info!(count = expired.len(), "Processing expired TTL rules");
    
    for entry in expired {
        // Acquire rollback coordination lock (see Rollback Safety section)
        let _guard = self.rollback_coordinator.acquire_removal_lock(&entry.rule_id).await?;
        
        // Transition state: Active → Expiring
        {
            let mut registry = self.registry.write();
            registry.mark_expiring(&entry.rule_id)?;
        }
        self.persister.persist(&entry)?;
        
        // Remove through firewall backend
        match self.firewall.remove_rule(&entry.rule_id).await {
            Ok(_) => {
                // Transition: Expiring → Expired
                let mut registry = self.registry.write();
                registry.mark_expired(&entry.rule_id)?;
                self.persister.remove(&entry.rule_id)?;
                
                info!(rule_id = %entry.rule_id, "TTL expired, rule removed");
            }
            Err(e) if is_rule_not_found(&e) => {
                // Rule already gone (manual removal or rollback)
                let mut registry = self.registry.write();
                registry.cancel(&entry.rule_id);
                self.persister.remove(&entry.rule_id)?;
                
                debug!(rule_id = %entry.rule_id, "TTL rule already removed");
            }
            Err(e) => {
                // Transition: Expiring → Failed
                let mut registry = self.registry.write();
                registry.mark_failed(&entry.rule_id)?;
                self.persister.persist(&entry)?;
                
                error!(rule_id = %entry.rule_id, error = %e, "TTL expiration failed");
                // Will be retried on next tick or agent restart
            }
        }
    }
    
    Ok(())
}
```

## Crash Recovery

### Startup Recovery Procedure

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Startup Recovery Algorithm                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Load TTL log from disk → Vec<TtlEntry>                          │
│                                                                     │
│  2. For each entry:                                                 │
│     match entry.state:                                              │
│       Active →                                                      │
│         if entry.expires_at <= now():                               │
│           queue_for_immediate_expiration(entry)                     │
│         else:                                                       │
│           add_to_registry(entry)                                    │
│                                                                     │
│       Expiring →                                                    │
│         // Crash during expiration - check actual state             │
│         if firewall.rule_exists(entry.rule_id):                     │
│           queue_for_immediate_expiration(entry)                     │
│         else:                                                       │
│           mark_expired_and_remove(entry)                            │
│                                                                     │
│       Failed →                                                      │
│         queue_for_immediate_expiration(entry)                       │
│                                                                     │
│       Expired | Cancelled →                                         │
│         remove_from_log(entry)  // Cleanup stale entries            │
│                                                                     │
│  3. Schedule timer for next expiration                              │
│                                                                     │
│  4. Process immediate expiration queue                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### State Machine

```
                    ┌──────────┐
                    │  Active  │
                    └────┬─────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
   ┌──────────┐    ┌──────────┐    ┌──────────┐
   │ Expiring │    │Cancelled │    │ (manual  │
   └────┬─────┘    └──────────┘    │ removal) │
        │                          └──────────┘
        │
   ┌────┴────┐
   │         │
   ▼         ▼
┌──────┐  ┌──────┐
│Expired│  │Failed│──────┐
└──────┘  └──┬───┘       │
             │           │
             └───────────┘
               (retry)

Terminal states: Expired, Cancelled
Restart states: Active, Expiring, Failed (resume processing)
```

## Rollback Coordination

### The Race Problem

```
Timeline showing race condition without coordination:

Thread 1 (Rollback)          Thread 2 (TTL Engine)
─────────────────────        ─────────────────────
                             Timer fires
                             Get expired rules: [rule-123]
Begin rollback               
Read journal: has rule-123   
                             Mark Expiring
                             Remove rule-123 ← SUCCEEDS
Remove rule-123 ← FAILS!     
Rollback reports failure!    Mark Expired
                             
Result: Rollback fails because TTL engine removed the rule first.
The rule WAS removed, but rollback doesn't know it's "expected".
```

### Solution: Coordination Lock

```rust
/// Coordinator for TTL and rollback operations
pub struct TtlRollbackCoordinator {
    /// Per-rule locks for removal coordination
    /// HashMap<RuleId, RwLock<RuleRemovalState>>
    removal_states: DashMap<RuleId, RuleRemovalState>,
    
    /// Global rollback lock
    /// When held, TTL expirations are deferred
    rollback_in_progress: AtomicBool,
    
    /// Condition variable for waiting on rollback completion
    rollback_complete: tokio::sync::Notify,
}

#[derive(Debug, Clone, Copy)]
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

impl TtlRollbackCoordinator {
    /// Called by TTL engine before removing an expired rule
    /// Returns a guard that must be held during removal
    pub async fn acquire_ttl_removal(&self, rule_id: &RuleId) 
        -> Result<RemovalGuard, CoordinationError> 
    {
        // If rollback is in progress, wait
        while self.rollback_in_progress.load(Ordering::SeqCst) {
            self.rollback_complete.notified().await;
        }
        
        // Try to transition: Active → TtlRemoving
        let state = self.removal_states.entry(rule_id.clone())
            .or_insert(RuleRemovalState::Active);
        
        match *state {
            RuleRemovalState::Active => {
                *state = RuleRemovalState::TtlRemoving;
                Ok(RemovalGuard { coordinator: self, rule_id: rule_id.clone() })
            }
            RuleRemovalState::RollbackRemoving => {
                // Rollback is handling this rule, skip
                Err(CoordinationError::RollbackInProgress)
            }
            _ => {
                // Already removed or being removed
                Err(CoordinationError::AlreadyRemoved)
            }
        }
    }
    
    /// Called by rollback engine before removing a rule
    pub async fn acquire_rollback_removal(&self, rule_id: &RuleId)
        -> Result<RemovalGuard, CoordinationError>
    {
        // Set rollback in progress flag
        self.rollback_in_progress.store(true, Ordering::SeqCst);
        
        let state = self.removal_states.entry(rule_id.clone())
            .or_insert(RuleRemovalState::Active);
        
        match *state {
            RuleRemovalState::Active => {
                *state = RuleRemovalState::RollbackRemoving;
                Ok(RemovalGuard { coordinator: self, rule_id: rule_id.clone() })
            }
            RuleRemovalState::TtlRemoving => {
                // TTL already started, wait for it to complete
                // The TTL engine will mark the rule as removed
                // Rollback can then skip this rule
                Err(CoordinationError::TtlInProgress)
            }
            RuleRemovalState::Removed => {
                // Already removed (by TTL or otherwise)
                // This is OK for rollback - rule is gone
                Err(CoordinationError::AlreadyRemoved)
            }
            _ => {
                Err(CoordinationError::AlreadyRemoved)
            }
        }
    }
}

/// RAII guard that marks removal complete on drop
pub struct RemovalGuard<'a> {
    coordinator: &'a TtlRollbackCoordinator,
    rule_id: RuleId,
}

impl Drop for RemovalGuard<'_> {
    fn drop(&mut self) {
        // Mark as removed
        self.coordinator.removal_states.insert(
            self.rule_id.clone(), 
            RuleRemovalState::Removed
        );
        
        // If we were in rollback mode, notify waiters
        if self.coordinator.rollback_in_progress.load(Ordering::SeqCst) {
            // Don't clear the flag here - rollback engine does that
        }
    }
}
```

### Integrated Removal Flow

```
TTL Expiration:
1. Timer fires
2. Get expired rules from registry
3. For each rule:
   a. coordinator.acquire_ttl_removal(rule_id)
      - If rollback in progress: wait
      - If already removing: skip
   b. Mark state: Active → Expiring
   c. Call firewall.remove_rule()
   d. Mark state: Expiring → Expired
   e. Drop RemovalGuard (marks Removed)

Rollback:
1. Begin rollback
2. coordinator.set_rollback_in_progress(true)
3. For each rule to restore:
   a. coordinator.acquire_rollback_removal(rule_id)
      - If TTL removing: wait or skip
      - If already removed: log and continue (not an error)
   b. Perform removal/restore
   c. Drop RemovalGuard
4. coordinator.set_rollback_in_progress(false)
5. Notify waiting TTL expirations
```

## Integration with Event Loop

The TTL engine integrates with the existing event loop via `tokio::select!`:

```rust
// In EventLoop::run()
loop {
    select! {
        biased;
        
        // Priority 1: Shutdown
        _ = shutdown_coordinator.wait_for_shutdown() => break,
        
        // Priority 2: TTL expirations (time-critical)
        tick = ttl_engine.next_tick() => {
            if let Some(tick) = tick {
                ttl_engine.process_expirations(tick).await?;
            }
        }
        
        // Priority 3: Events
        event = event_dispatcher.next() => { ... }
        
        // Priority 4: Health checks
        _ = health_interval.tick() => { ... }
    }
}
```

## API

```rust
/// TTL Engine public interface
pub struct TtlEngine {
    registry: Arc<RwLock<TtlRegistry>>,
    persister: TtlPersister,
    timer: TtlWheelTimer,
    coordinator: Arc<TtlRollbackCoordinator>,
    firewall: Arc<dyn FirewallBackend>,
}

impl TtlEngine {
    /// Create a new TTL engine
    pub async fn new(
        config: TtlConfig,
        firewall: Arc<dyn FirewallBackend>,
        coordinator: Arc<TtlRollbackCoordinator>,
    ) -> Result<Self, TtlError>;
    
    /// Register a rule with TTL
    /// Called after rule is successfully added to firewall
    pub async fn register(&self, rule_id: RuleId, ttl: Duration) -> Result<(), TtlError>;
    
    /// Cancel TTL (rule removed manually or by rollback)
    /// Idempotent - no error if rule not found
    pub fn cancel(&self, rule_id: &RuleId);
    
    /// Extend TTL for an existing rule
    pub fn extend(&self, rule_id: &RuleId, additional: Duration) -> Result<(), TtlError>;
    
    /// Get remaining TTL for a rule
    pub fn remaining(&self, rule_id: &RuleId) -> Option<Duration>;
    
    /// Get all active TTL entries (for debugging/status)
    pub fn list_active(&self) -> Vec<TtlEntry>;
    
    /// Get the next expiration tick (for select!)
    pub async fn next_tick(&mut self) -> Option<TtlTick>;
    
    /// Process expired rules (called when tick fires)
    pub async fn process_expirations(&self, tick: TtlTick) -> Result<(), TtlError>;
    
    /// Recover state after restart
    pub async fn recover(&self) -> Result<RecoveryStats, TtlError>;
    
    /// Shutdown the TTL engine gracefully
    pub async fn shutdown(&self) -> Result<(), TtlError>;
}

#[derive(Debug)]
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
    /// How often to compact the log file
    pub compaction_interval: Duration,
    /// Log file size threshold for forced compaction
    pub compaction_threshold_bytes: u64,
}
```

## File Format

### TTL State File (`/var/lib/whitequbit/ttl.log`)

JSONL format for crash resilience and easy recovery:

```jsonl
{"seq":1,"timestamp_ms":1703203200000,"op":{"Register":{"rule_id":"abc-123","expires_at_ms":1703206800000,"created_at_ms":1703203200000,"original_ttl_secs":3600,"state":"Active","generation":1}}}
{"seq":2,"timestamp_ms":1703203300000,"op":{"Register":{"rule_id":"def-456","expires_at_ms":1703210400000,"created_at_ms":1703203300000,"original_ttl_secs":7200,"state":"Active","generation":1}}}
{"seq":3,"timestamp_ms":1703206800000,"op":{"Update":{"rule_id":"abc-123","state":"Expired","generation":2}}}
{"seq":4,"timestamp_ms":1703206800100,"op":{"Remove":{"rule_id":"abc-123"}}}
{"seq":5,"timestamp_ms":1703210000000,"op":{"Compacted":{"up_to_seq":4}}}
```

## Performance Characteristics

| Operation | Time Complexity | Notes |
|-----------|-----------------|-------|
| Register TTL | O(log n) | BTreeMap insert |
| Cancel TTL | O(log n) | BTreeMap remove |
| Get next expiration | O(1) | BTreeMap first |
| Process N expirations | O(N log n) | N removals from BTreeMap |
| Recovery | O(n) | Linear scan of log file |
| Persist entry | O(1) | Append to log |
| Compaction | O(n) | Rewrite entire log |

Memory: ~200 bytes per TTL entry (estimate)

## Error Handling

| Error | Handling | Recovery |
|-------|----------|----------|
| Persist failure | Log error, continue (TTL will be lost on restart) | On restart, rule remains but no TTL |
| Remove failure | Mark as Failed, retry on next tick | Eventually consistent |
| Timer drift | Use absolute timestamps, catch up on wake | No accumulating drift |
| Coordinator deadlock | Timeout on lock acquisition | Log and skip, retry later |

## Security Considerations

1. **No privilege escalation**: TTL engine uses same firewall backend as normal operations
2. **Input validation**: TTL durations validated (min 1s, max 30 days)
3. **Audit logging**: All expirations logged with rule details
4. **Rate limiting**: Can limit number of concurrent expirations
5. **Crash safety**: State persisted before state transitions

## Testing Strategy

1. **Unit tests**: State machine transitions, timer scheduling, coordination logic
2. **Integration tests**: Full flow with mock firewall
3. **Crash tests**: Kill process at each state, verify recovery
4. **Race tests**: Concurrent expiration and rollback operations
5. **Time travel tests**: Mock time to test edge cases (exact expiration, batch expiration)
