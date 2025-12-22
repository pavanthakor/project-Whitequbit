# Security Versioning System Design

## Overview

The Security Versioning System provides deterministic, content-addressable version tracking for
security state changes. Every security-relevant modification generates a new version that is:

1. **Deterministic** - Same security state always produces the same version hash
2. **Ordered** - Versions have a total ordering via epoch + sequence numbering
3. **Persistent** - Version history survives restarts via Write-Ahead Log (WAL)
4. **Observable** - Downstream systems receive notifications of version changes

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        VersionManager                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Orchestrates version creation from SecuritySnapshots               │ │
│  │  • Rate limiting (min interval between versions)                    │ │
│  │  • Content-hash computation via BLAKE3                              │ │
│  │  • Change detection (skip if no content change)                     │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────┬────────────────────────────────────────────────────┘
                      │ record_change()
                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         VersionStore                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Persistent storage with WAL (Write-Ahead Log)                      │ │
│  │  • JSONL append-only format for durability                          │ │
│  │  • In-memory cache for fast queries                                 │ │
│  │  • Chain integrity (parent hash linking)                            │ │
│  │  • Atomic file operations                                           │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────┬────────────────────────────────────────────────────┘
                      │ notify()
                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                       VersionNotifier                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  Broadcast channel for version change events                        │ │
│  │  • Multiple subscribers supported                                    │ │
│  │  • Async tokio::sync::broadcast                                     │ │
│  │  • Built-in subscribers: Logging, File                              │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

## Version Format

### SecurityVersion

Each version has three components:

```
Epoch.Sequence | ContentHash
  │       │           │
  │       │           └── BLAKE3 hash of SecuritySnapshot (first 16 hex chars)
  │       └── Incrementing counter within epoch
  └── Unix timestamp when epoch started (agent restart)
```

**Examples:**
```
1735689600.1  | a1b2c3d4e5f6g7h8    (first version of epoch)
1735689600.42 | x9y8z7w6v5u4t3s2    (42nd version of epoch)
1735700000.1  | b2c3d4e5f6g7h8i9    (new epoch after restart)
```

### Ordering

Versions support total ordering:

1. **Cross-epoch**: Higher epoch wins
2. **Within-epoch**: Higher sequence wins
3. **Ties**: Lexicographic content hash comparison (for consistency)

```rust
// Ordering examples
v1735689600.5  < v1735689600.10  // Same epoch, higher sequence wins
v1735689600.99 < v1735700000.1   // Higher epoch always wins
```

## Content Hashing

### Determinism Guarantee

The version hash is computed from a SecuritySnapshot's canonical byte representation:

```rust
// Canonical serialization process
1. SecuritySnapshot.canonical_bytes()
   └── BTreeMap/BTreeSet for deterministic field ordering
   └── Consistent number formatting
   └── Stable enum serialization

2. BLAKE3 hash
   └── 256-bit cryptographic hash
   └── Truncated to 16 hex characters for display

3. Same security state → Same hash (content-addressable)
```

### What's Included

The content hash reflects:

| Component        | Fields Hashed                               |
|------------------|---------------------------------------------|
| Open Ports       | Port, protocol, state, process (if known)   |
| Firewall Rules   | Direction, ports, CIDRs, action (sanitized) |
| Services         | Name, status, enabled state, category       |
| Auth Posture     | SSH level, password policy, MFA status      |

### What's Excluded

- Timestamps (would break determinism)
- Transient process PIDs
- Exact IP addresses in rules (sanitized to CIDR ranges)

## Persistence

### Write-Ahead Log (WAL)

Version history is persisted to a JSONL file:

```json
{"version":{"epoch":1735689600,"sequence":1,"content_hash":"a1b2c3d4"},"parent_hash":"genesis","timestamp":"2025-01-01T00:00:00Z","change_type":"Snapshot","summary":"Initial capture"}
{"version":{"epoch":1735689600,"sequence":2,"content_hash":"b2c3d4e5"},"parent_hash":"a1b2c3d4","timestamp":"2025-01-01T00:01:00Z","change_type":"RuleAdded","summary":"Added firewall rule"}
```

### Recovery Process

On startup:

```
1. Detect existing WAL file
2. Read and parse all entries
3. Validate chain integrity (parent_hash linking)
4. Restore in-memory state
5. Start new epoch (preserves history, fresh sequence)
```

### Chain Integrity

Each version's parent_hash must match the previous version's content_hash:

```
Genesis ──────► Version1 ──────► Version2 ──────► Version3
           parent="genesis"  parent=v1.hash  parent=v2.hash
```

Integrity violations are detected during recovery and reported as errors.

## Change Types

The versioning system tracks what triggered each version change:

| ChangeType        | Description                                    |
|-------------------|------------------------------------------------|
| `Snapshot`        | Periodic security state capture                |
| `RuleAdded`       | Firewall rule was added                        |
| `RuleRemoved`     | Firewall rule was removed                      |
| `RuleModified`    | Firewall rule was updated                      |
| `ServiceChanged`  | Critical service state changed                 |
| `PortChanged`     | Network port opened/closed                     |
| `AuthChanged`     | Authentication posture changed                 |
| `PolicyUpdate`    | Security policy was modified                   |
| `ManualOverride`  | Administrator forced version bump              |
| `Recovery`        | System recovered from failure                  |
| `Rollback`        | Security change was rolled back                |

## Notifications

### VersionChangeEvent

When a version changes, subscribers receive:

```rust
VersionChangeEvent {
    old_version: Option<SecurityVersion>,  // None for genesis
    new_version: SecurityVersion,
    change_type: VersionChangeType,
    summary: String,
    timestamp: DateTime<Utc>,
}
```

### Built-in Subscribers

1. **LoggingSubscriber**: Logs version changes via tracing
2. **FileSubscriber**: Appends changes to a separate notification file

### Custom Subscribers

Implement `VersionSubscriber` trait for custom handling:

```rust
#[async_trait]
pub trait VersionSubscriber: Send + Sync {
    fn name(&self) -> &str;
    async fn on_version_change(&self, event: VersionChangeEvent) -> Result<(), String>;
}
```

## Rate Limiting

To prevent version spam:

```rust
VersionManagerConfig {
    min_version_interval: Duration::from_secs(1),  // Default 1 second
    // ...
}
```

Attempts to create versions faster than the minimum interval return an error.

## Usage Examples

### Basic Version Recording

```rust
// Create manager with persistent storage
let config = VersionManagerConfig::builder()
    .wal_path("/var/lib/whitequbit/versions.wal")
    .build();
let manager = VersionManager::new(config)?;

// Record a security snapshot
let snapshot: SecuritySnapshot = collect_security_state().await?;
let version = manager.from_snapshot(&snapshot, "Periodic scan")?;

println!("Security Version: {}", version);
// Output: Security Version: 1735689600.42
```

### Subscribing to Changes

```rust
// Get notifier and subscribe
let notifier = manager.notifier();
let mut rx = notifier.subscribe()?;

// Handle events (in async task)
tokio::spawn(async move {
    while let Ok(event) = rx.recv().await {
        println!("Version changed: {} -> {}", 
            event.old_version.map(|v| v.to_string()).unwrap_or("genesis".into()),
            event.new_version
        );
        // Trigger downstream actions...
    }
});
```

### Version Comparison

```rust
// Compare two versions
let v1 = manager.current_version()?;
// ... some changes ...
let v2 = manager.current_version()?;

match v1.cmp(&v2) {
    Ordering::Less => println!("Security state advanced"),
    Ordering::Equal => println!("No security changes"),
    Ordering::Greater => unreachable!("Versions never go backwards"),
}
```

### Querying History

```rust
// Get version history
let history = manager.history()?;

// Check ancestry
let is_ancestor = manager.is_ancestor(&old_version, &new_version)?;

// Get versions in time range
let recent = manager.versions_since(yesterday)?;
```

## Integration Points

### With Snapshot System

The versioning system is designed to integrate with `SecuritySnapshot`:

```rust
// Collect snapshot (from observability/snapshot.rs)
let snapshot = SnapshotBuilder::new(config)
    .add_port_collector(collector)
    .add_firewall_collector(firewall)
    .build()
    .collect()
    .await?;

// Generate version
let version = manager.from_snapshot(&snapshot, "Scheduled capture")?;
```

### With Rollback Engine

On rollback, record the change:

```rust
// After rollback completes
manager.record_change(
    new_snapshot.compute_security_version(),
    format!("Rolled back {} rules", count),
    VersionChangeType::Rollback,
    Some(metadata),
)?;
```

### With Audit System

Version changes can be correlated with audit entries:

```rust
// Record audit entry with version reference
audit_logger.record(AuditEntry {
    security_version: manager.current_version()?.to_string(),
    // ...
})?;
```

## Performance Characteristics

| Operation               | Complexity | Notes                          |
|-------------------------|------------|--------------------------------|
| Record version          | O(1)       | Append to WAL + hash table     |
| Get current version     | O(1)       | Cached in memory               |
| Check ancestry          | O(n)       | Walk parent chain              |
| Recover from WAL        | O(n)       | Read all entries on startup    |
| Content hash compute    | O(snapshot size) | BLAKE3 is fast            |

## Security Considerations

1. **WAL File Permissions**: Should be 0600 (owner read/write only)
2. **Hash Truncation**: 16 hex chars = 64 bits (collision-resistant for versioning)
3. **No Secrets in Versions**: Snapshots sanitize sensitive data before hashing
4. **Chain Integrity**: Tampering detected via parent hash validation

## Configuration

```toml
[versioning]
# Path to Write-Ahead Log
wal_path = "/var/lib/whitequbit/versions.wal"

# Minimum time between versions (rate limiting)
min_version_interval_secs = 1

# Maximum versions to keep in memory (oldest pruned)
max_cached_versions = 10000

# Notification channel capacity
notification_buffer_size = 1024
```

## Error Handling

| Error Type                  | Cause                                      | Recovery                    |
|-----------------------------|--------------------------------------------|-----------------------------|
| `StorageError`              | WAL write failure                          | Retry or fail operation     |
| `ChainIntegrityViolation`   | Parent hash mismatch                       | Investigate tampering       |
| `RateLimited`               | Too many versions too fast                 | Wait and retry              |
| `InvalidContentHash`        | Malformed hash string                      | Validate input              |
| `RecoveryFailed`            | WAL corruption                             | Start fresh epoch           |

## Future Enhancements

1. **Compaction**: Periodically compact old WAL entries to snapshot file
2. **Remote Sync**: Replicate version history to central server
3. **Merkle Tree**: Enable efficient range proofs for version sets
4. **Semantic Versioning**: Add major.minor.patch semantic layer
5. **Diff Reconstruction**: Store deltas to enable state reconstruction
