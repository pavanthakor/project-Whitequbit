# Security Snapshot Module Design

**Module:** `src/observability/snapshot.rs`  
**Version:** 1.0  
**Last Updated:** 2025-12-22

---

## Overview

The Security Snapshot module captures point-in-time system security state for drift detection, change auditing, compliance verification, and incident response.

## Design Principles

| Principle | Implementation |
|-----------|---------------|
| **No Secrets** | Never captures passwords, keys, tokens, or sensitive IP addresses |
| **Serializable** | Full JSON support for storage and transmission |
| **Diffable** | Deterministic ordering via BTreeSet/BTreeMap + sorted vectors |
| **Fast** | Parallel collection, minimal syscalls, cached where safe |
| **Versioned** | Content-addressable via deterministic BLAKE3 hash |

---

## Snapshot Contents

### 1. Open Ports (`PortSummary`)

```rust
pub struct OpenPort {
    pub protocol: PortProtocol,      // TCP or UDP
    pub port: u16,                    // Port number
    pub bind_address: IpAddr,         // 0.0.0.0, ::, or specific
    pub state: PortState,             // Listen, Established, etc.
    pub process_name: Option<String>, // e.g., "sshd" (non-sensitive)
    pub is_privileged: bool,          // port < 1024
}
```

**Collected metrics:**
- TCP port count
- UDP port count
- Privileged port count
- Wildcard-bound port count

### 2. Firewall Summary (`FirewallSummary`)

```rust
pub struct FirewallRuleSummary {
    pub id: String,                // Hash-based ID (not original)
    pub chain: String,             // iptables chain or equivalent
    pub action: RuleAction,        // Allow, Block, Reject, RateLimit
    pub direction: TrafficDirection,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub has_source_filter: bool,   // Whether IPs are filtered (not which)
    pub has_dest_filter: bool,
    pub agent_managed: bool,       // Created by this agent
    pub priority: i32,
}
```

**Note:** Actual IP addresses are NOT included to avoid leaking sensitive network topology.

### 3. Critical Services (`ServicesSummary`)

```rust
pub struct CriticalService {
    pub name: String,
    pub status: ServiceStatus,           // Running, Stopped, Failed
    pub enabled: bool,                   // Enabled at boot
    pub is_security_service: bool,
    pub category: ServiceCategory,       // Authentication, Firewall, Audit, etc.
}
```

**Categories:**
- `Authentication` - sshd, pam
- `Firewall` - iptables, nftables, firewalld
- `Audit` - auditd, rsyslog
- `IntrusionDetection` - fail2ban, ossec
- `AntiMalware` - clamav
- `Network` - networkd, dhcpd
- `System` - systemd, cron

### 4. Authentication Posture (`AuthPosture`)

```rust
pub struct AuthPosture {
    pub ssh_hardening: SshHardeningLevel,     // Hardened, Partial, Default
    pub root_login_disabled: bool,
    pub password_auth_disabled: bool,
    pub users_with_shell: usize,
    pub sudo_users: usize,
    pub mac_enforcing: bool,                  // SELinux/AppArmor
    pub mac_system: Option<String>,
    pub password_policy: PasswordPolicyStrength,
    pub mfa_configured: bool,
    pub recent_failed_logins: usize,
    pub audit_enabled: bool,
}
```

**Security Score (0-100):**
- Base: 50 points
- SSH hardened: +15
- Root login disabled: +10
- Password auth disabled: +10
- MAC enforcing: +10
- Strong password policy: +5
- MFA configured: +10
- Audit enabled: +5

---

## Versioning Strategy

### Security Version Hash

Each snapshot has a deterministic `security_version` computed as:

```
security_version = BLAKE3(
    canonical_bytes(ports) ||
    0xFF ||
    canonical_bytes(firewall) ||
    0xFF ||
    canonical_bytes(services) ||
    0xFF ||
    canonical_bytes(auth_posture)
)[0:32]  // First 16 bytes = 32 hex chars
```

### Canonical Byte Encoding

Each component produces deterministic bytes:

1. **Ports**: Sorted by (protocol, port, address), then concatenated
2. **Firewall**: Enabled flag + defaults + sorted rules
3. **Services**: Sorted by name, status encoded as u8
4. **Auth Posture**: Fixed-order field encoding

### Properties

| Property | Description |
|----------|-------------|
| **Deterministic** | Same security state → same hash |
| **Content-Addressable** | Hash uniquely identifies state |
| **Order-Independent** | Input order doesn't affect hash |
| **Change Detection** | Different hash = something changed |

---

## Snapshot Comparison

### Diff Structure

```rust
pub struct SnapshotDiff {
    pub old_version: String,
    pub new_version: String,
    pub old_timestamp: DateTime<Utc>,
    pub new_timestamp: DateTime<Utc>,
    pub duration_seconds: i64,
    pub version_changed: bool,
    pub score_delta: i16,          // Negative = degraded
    pub changes: Vec<SnapshotChange>,
    pub ports_added: usize,
    pub ports_removed: usize,
    pub rules_added: usize,
    pub rules_removed: usize,
    pub service_changes: usize,
}
```

### Change Detection

```rust
pub enum ChangeType {
    Added,
    Removed,
    Modified,
}

pub struct SnapshotChange {
    pub category: String,      // "ports", "firewall", "services", "auth"
    pub change_type: ChangeType,
    pub description: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}
```

### Usage Example

```rust
let snapshot1 = collector.collect().await?;
// ... time passes, system changes ...
let snapshot2 = collector.collect().await?;

if snapshot1.differs_from(&snapshot2) {
    let diff = snapshot1.diff(&snapshot2);
    
    if diff.security_degraded() {
        alert!("Security posture degraded: {} -> {}",
            snapshot1.security_score,
            snapshot2.security_score);
    }
    
    for change in diff.changes {
        audit_log!("{}: {:?} - {}",
            change.category,
            change.change_type,
            change.description);
    }
}
```

---

## Snapshot Chaining

Snapshots can form a chain via `parent_hash`:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Snapshot 1  │────▶│ Snapshot 2  │────▶│ Snapshot 3  │
│ seq: 0      │     │ seq: 1      │     │ seq: 2      │
│ parent: None│     │ parent: v1  │     │ parent: v2  │
│ hash: v1    │     │ hash: v2    │     │ hash: v3    │
└─────────────┘     └─────────────┘     └─────────────┘
```

This enables:
- **Ancestry tracking**: Walk back through security state history
- **Gap detection**: Missing sequence numbers indicate missed snapshots
- **Integrity**: Broken chain indicates tampering or data loss

---

## Collection Architecture

### Collector Traits

```rust
#[async_trait]
pub trait PortCollector: Send + Sync {
    async fn collect(&self) -> SnapshotResult<Vec<OpenPort>>;
}

#[async_trait]
pub trait FirewallCollector: Send + Sync {
    async fn collect(&self) -> SnapshotResult<FirewallSummary>;
}

#[async_trait]
pub trait ServiceCollector: Send + Sync {
    async fn collect(&self) -> SnapshotResult<Vec<CriticalService>>;
}

#[async_trait]
pub trait AuthCollector: Send + Sync {
    async fn collect(&self) -> SnapshotResult<AuthPosture>;
}
```

### Orchestrator

```rust
let collector = SnapshotCollector::new(SnapshotConfig::default())
    .with_port_collector(Box::new(LinuxPortCollector))
    .with_firewall_collector(Box::new(IptablesCollector))
    .with_service_collector(Box::new(SystemdCollector))
    .with_auth_collector(Box::new(LinuxAuthCollector));

let snapshot = collector.collect().await?;
```

### Collection Timing

Target: **< 100ms** for typical systems

| Component | Expected Time | Method |
|-----------|--------------|--------|
| Ports | ~10ms | `/proc/net/tcp`, `/proc/net/udp` |
| Firewall | ~20ms | `iptables-save` or netlink |
| Services | ~30ms | D-Bus to systemd |
| Auth Posture | ~20ms | Config file parsing |

---

## Serialization

### JSON Output

```json
{
  "metadata": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2025-12-22T10:30:00Z",
    "hostname": "web-server-01",
    "agent_version": "0.1.0",
    "collection_duration_ms": 87,
    "parent_hash": "a1b2c3d4e5f6...",
    "sequence": 42
  },
  "ports": {
    "ports": [
      {"protocol": "tcp", "port": 22, "bind_address": "0.0.0.0", ...}
    ],
    "tcp_count": 5,
    "udp_count": 2,
    "privileged_count": 3,
    "wildcard_count": 4
  },
  "firewall": {
    "enabled": true,
    "default_inbound": "block",
    "default_outbound": "allow",
    "total_rules": 15,
    "agent_managed_rules": 3,
    "rules": [...],
    "backend": "iptables"
  },
  "services": {
    "services": [...],
    "running_count": 8,
    "stopped_count": 2,
    "failed_count": 0,
    "security_services_running": 5,
    "has_security_issues": false
  },
  "auth_posture": {
    "ssh_hardening": "hardened",
    "root_login_disabled": true,
    ...
  },
  "security_version": "a1b2c3d4e5f67890a1b2c3d4e5f67890",
  "security_score": 85
}
```

---

## Security Considerations

### What's NOT Included

| Excluded | Reason |
|----------|--------|
| Actual IP addresses in rules | Network topology leak |
| User passwords/hashes | Credential exposure |
| Private keys | Key compromise |
| API tokens | Token theft |
| Full file paths | Reconnaissance aid |
| Process arguments | May contain secrets |

### What IS Included (Safe)

| Included | Justification |
|----------|---------------|
| Port numbers | Public knowledge (port scans) |
| Service names | Public knowledge |
| Binary yes/no for filters | No specific IPs |
| Counts and aggregates | Statistical only |
| Configuration state | Policy, not secrets |

---

## Integration Points

### Health Check Integration

```rust
impl HealthReporter for SnapshotCollector {
    fn name(&self) -> &str { "security_snapshot" }
    
    fn check_health(&self) -> ComponentHealth {
        // Check if last collection succeeded
        // Check if security score is acceptable
    }
}
```

### Audit Log Integration

```rust
// After collecting snapshot
audit.log(AuditEvent::SecuritySnapshot {
    version: snapshot.security_version,
    score: snapshot.security_score,
    duration_ms: snapshot.metadata.collection_duration_ms,
});

// On security degradation
audit.log(AuditEvent::SecurityDegraded {
    old_score: 85,
    new_score: 70,
    changes: diff.changes,
});
```

### Metrics Integration

```rust
metrics.security_score.set(snapshot.security_score as i64);
metrics.open_ports.set(snapshot.ports.ports.len() as i64);
metrics.firewall_rules.set(snapshot.firewall.total_rules as i64);
```

---

## Testing

### Unit Tests (10 tests, all passing)

1. `test_port_summary_determinism` - Same ports, different order → same hash
2. `test_security_version_determinism` - Identical state → identical hash
3. `test_security_version_changes_on_diff` - Different state → different hash
4. `test_auth_posture_score` - Score calculation correctness
5. `test_snapshot_builder` - Builder pattern works
6. `test_snapshot_diff_no_changes` - No-change diff detection
7. `test_snapshot_diff_with_changes` - Change detection works
8. `test_services_summary_security_issues` - Security issue detection
9. `test_serialization_roundtrip` - JSON serialize/deserialize

### Integration Tests (recommended)

1. Collect real port data on test system
2. Collect real firewall rules
3. Full snapshot collection timing
4. Diff across system changes

---

## Future Enhancements

1. **CBOR serialization** for compact binary format
2. **Compression** for historical storage
3. **Bloom filter** for fast "likely changed" checks
4. **Parallel collection** using tokio::join!
5. **Platform collectors** for Windows, macOS
6. **Webhook notifications** on security degradation
