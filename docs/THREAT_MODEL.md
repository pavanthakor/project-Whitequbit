# WhiteQubit Agent - Threat Model

**Document Version:** 1.0  
**Last Updated:** 2025-12-22  
**Classification:** Engineering Security Documentation  
**Author:** Principal Security Engineering

---

## Executive Summary

This document defines the threat model for WhiteQubit Agent, a system-level security daemon capable of modifying firewall rules, managing services, and altering system security state. Given the agent's elevated privileges and critical responsibilities, a compromised or malfunctioning agent could leave the system **less secure than before intervention**.

**Core Security Invariant:** The system must NEVER be left in a less secure state than before the agent acted, even under adversarial conditions, partial failures, or crashes.

---

## 1. Agent Capabilities and Permissions

### 1.1 What This Agent Is ALLOWED To Do

| Category | Permitted Actions | Constraints |
|----------|------------------|-------------|
| **Firewall Management** | Add blocking rules, remove agent-created rules, flush agent-managed chains | Only to chains the agent owns; never to system-critical chains |
| **Service Management** | Stop compromised services, restart agent-managed services | Only services on the allowlist; never critical system services |
| **Network Isolation** | Block malicious IP addresses, rate-limit suspicious traffic | Time-bounded rules; automatic expiration required |
| **Audit & Logging** | Write to audit log, rotate logs, export audit data | Append-only; no deletion or modification of existing entries |
| **Self-Management** | Graceful shutdown, configuration reload, health reporting | No privilege escalation; no self-update without verification |

### 1.2 What This Agent Is NEVER Allowed To Do

These are **hard security invariants** that must be enforced at multiple layers:

| Prohibition | Rationale | Enforcement Mechanism |
|-------------|-----------|----------------------|
| **Disable the host firewall entirely** | Would leave system unprotected | Policy engine rejects; no API for this action |
| **Remove rules it did not create** | Could disable legitimate security controls | Rule tagging; ownership verification |
| **Execute arbitrary commands** | RCE vector; violates least privilege | No shell execution; hardcoded action types only |
| **Modify authentication systems** | Could lock out administrators | Action type not implemented; policy denies |
| **Access sensitive credential stores** | Credential theft risk | Seccomp/Landlock blocks; no capability granted |
| **Communicate with external networks** | C2 channel prevention | Outbound traffic blocked by sandbox |
| **Disable its own audit logging** | Anti-forensics prevention | No API; audit subsystem is immutable once started |
| **Modify its own binary or configuration** | Self-modification attacks | Read-only mounts; no write capability to /etc or /usr |
| **Bypass privilege separation** | Privilege escalation | Capabilities dropped irreversibly; no SUID |
| **Act without authentication** | Unauthorized command injection | All IPC requires cryptographic authentication |
| **Execute during recovery without human confirmation** | Crash-loop attacks | Recovery mode requires explicit unlock |

---

## 2. Trust Boundaries

### 2.1 Trust Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              UNTRUSTED ZONE                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Network   │  │   User      │  │  External   │  │   Malicious Processes   │ │
│  │   Traffic   │  │   Input     │  │   APIs      │  │   on Same Host          │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
└─────────┼────────────────┼────────────────┼─────────────────────┼───────────────┘
          │                │                │                     │
══════════╪════════════════╪════════════════╪═════════════════════╪═══════════════
          │      TRUST BOUNDARY: Input Validation & Authentication│
══════════╪════════════════╪════════════════╪═════════════════════╪═══════════════
          ▼                ▼                ▼                     ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           VALIDATION ZONE                                        │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                        Input Sanitization Layer                            │  │
│  │  • Schema validation       • Size limits        • Character filtering     │  │
│  │  • Cryptographic signature verification         • Rate limiting           │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
════════════════════════════════════════╪═════════════════════════════════════════
                 TRUST BOUNDARY: Policy Authorization                              
════════════════════════════════════════╪═════════════════════════════════════════
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           POLICY ZONE                                            │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                          Policy Engine                                     │  │
│  │  • Action allowlist check      • Target validation    • Rate enforcement  │  │
│  │  • Deny-by-default             • Conflict detection   • Scope limitation │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
════════════════════════════════════════╪═════════════════════════════════════════
                 TRUST BOUNDARY: Execution Sandbox                                 
════════════════════════════════════════╪═════════════════════════════════════════
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           EXECUTION ZONE (Sandboxed)                            │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                         Action Executor                                    │  │
│  │  • seccomp syscall filtering   • Landlock filesystem isolation            │  │
│  │  • Capability restrictions     • Resource limits (cgroups)                │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
════════════════════════════════════════╪═════════════════════════════════════════
                 TRUST BOUNDARY: Kernel Interface                                  
════════════════════════════════════════╪═════════════════════════════════════════
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           KERNEL ZONE (Trusted)                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  netfilter  │  │   systemd   │  │    VFS      │  │      Audit Subsystem    │ │
│  │  (iptables) │  │   (D-Bus)   │  │             │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Trust Relationships

| Entity | Trust Level | Verification Method |
|--------|-------------|---------------------|
| Kernel | Fully Trusted | N/A (TCB) |
| Agent Binary | Trusted after verification | Code signing; binary hash in TPM/IMA |
| Configuration File | Trusted at startup | Signature verification; integrity monitoring |
| IPC Commands | Untrusted until authenticated | Ed25519 signature + timestamp + nonce |
| Event Sources | Untrusted | Schema validation; rate limiting |
| Supervisor Process | Semi-trusted | Mutual authentication; limited commands |
| Audit Log Storage | Write-trusted, tamper-evident | Hash chaining; optional remote attestation |

---

## 3. Failure Assumptions

### 3.1 Expected Failure Modes

The agent is designed assuming these failures WILL occur:

| Failure Mode | Probability | Impact | Mitigation |
|--------------|-------------|--------|------------|
| **Crash during action execution** | High | Partial state change | WAL ensures atomic commit/rollback |
| **Power loss / SIGKILL** | Medium | Uncommitted changes | Recovery on startup; conservative defaults |
| **Disk full** | Medium | Cannot log/checkpoint | Pre-allocated journal; graceful degradation |
| **Memory exhaustion** | Medium | OOM kill | Resource limits; bounded queues |
| **Malformed input causing panic** | Medium | Process termination | Supervisor restart; panic handler logs |
| **Network partition** | High | Cannot reach control plane | Local policy cache; fail-closed |
| **Clock skew / NTP attacks** | Low | Replay attacks | Monotonic counters; sequence numbers |
| **Malicious commands via IPC** | Medium | Unauthorized actions | Cryptographic auth; policy enforcement |

### 3.2 Crash Recovery Guarantees

```
┌─────────────────────────────────────────────────────────────────┐
│                    RECOVERY STATE MATRIX                        │
├─────────────────────────────────────────────────────────────────┤
│  Crash Point              │  Recovery Action    │  Safety       │
├───────────────────────────┼─────────────────────┼───────────────┤
│  Before WAL write         │  No action needed   │  ✓ Safe       │
│  After WAL, before exec   │  Skip (mark failed) │  ✓ Safe       │
│  During execution         │  Rollback via WAL   │  ✓ Safe       │
│  After exec, before ack   │  Verify & confirm   │  ✓ Safe       │
│  During rollback          │  Retry rollback     │  ✓ Safe       │
│  Repeated crash (>3x)     │  STOP, require human│  ✓ Fail-safe  │
└───────────────────────────┴─────────────────────┴───────────────┘
```

### 3.3 Failure Hierarchy (Fail-Safe Ordering)

When multiple failures occur simultaneously, the agent prioritizes safety:

1. **Protect existing security controls** (never remove firewall rules under uncertainty)
2. **Preserve audit trail** (never lose evidence of what happened)
3. **Maintain rollback capability** (never commit without compensation ready)
4. **Ensure graceful degradation** (stop accepting new work, not crash)
5. **Signal for human intervention** (supervisor escalation)

---

## 4. Safe Default Behaviors

### 4.1 Deny-by-Default Policies

| Scenario | Default Behavior | Override Requirement |
|----------|------------------|---------------------|
| Unknown action type | Reject | Cannot override |
| Invalid signature on command | Reject | Cannot override |
| Target not in allowlist | Reject | Explicit policy rule |
| Rate limit exceeded | Reject | Cannot override |
| Policy evaluation error | Reject (fail-closed) | Cannot override |
| Unknown event source | Log and ignore | Explicit source registration |
| Ambiguous state during recovery | Do nothing, alert | Human confirmation |

### 4.2 Secure Defaults for Actions

| Action Type | Secure Default |
|-------------|----------------|
| Firewall rule creation | Rules auto-expire after 24 hours unless confirmed |
| Service restart | Maximum 3 restarts per hour per service |
| IP blocking | Blocks are temporary (1 hour default); permanent requires confirmation |
| Any destructive action | Requires explicit `--confirm` flag in command |

### 4.3 Communication Defaults

| Channel | Default State | Security Properties |
|---------|---------------|---------------------|
| IPC socket | Enabled, authenticated only | Unix socket with restrictive permissions |
| Network listener | **Disabled** | Must be explicitly enabled with TLS + mTLS |
| Outbound connections | **Blocked** | Sandbox prevents; no legitimate use case |
| Syslog forwarding | Local only | Remote requires explicit configuration |

---

## 5. Attack Surface Analysis

### 5.1 Attack Vectors and Mitigations

| Attack Vector | Threat | Mitigation | Residual Risk |
|---------------|--------|------------|---------------|
| **Malicious IPC command** | Arbitrary action execution | Crypto auth, policy engine, allowlist | Low - requires key compromise |
| **Compromised control plane** | Mass agent weaponization | Local policy overrides, rate limits | Medium - depends on architecture |
| **Privilege escalation via agent** | Root access | Capability dropping, seccomp, no shell | Low - hardened execution |
| **Agent binary replacement** | Complete compromise | Immutable root FS, IMA, code signing | Low - requires root already |
| **Configuration tampering** | Policy bypass | Signature verification, integrity monitoring | Low - requires root already |
| **Audit log tampering** | Cover tracks | Hash chaining, remote backup, append-only | Low - cryptographic protection |
| **Denial of service (crash loop)** | Agent unavailable | Supervisor backoff, circuit breaker | Medium - availability impact only |
| **Replay attacks** | Re-execute old commands | Timestamp + nonce + sequence number | Low - cryptographic protection |
| **Race conditions** | Inconsistent state | WAL atomicity, state machine invariants | Low - designed out |
| **Resource exhaustion** | Crash/OOM | Bounded queues, rate limits, watchdog | Low - resource controls |

### 5.2 Threat Actors

| Actor | Capability | Motivation | Relevant Attacks |
|-------|------------|------------|------------------|
| **External Attacker** | Network access only | Data theft, ransomware | IPC exploitation, DoS |
| **Compromised Service** | Local user access | Lateral movement | IPC command injection |
| **Insider (Malicious Admin)** | Root access | Sabotage, cover tracks | Audit tampering, policy bypass |
| **Supply Chain Attack** | Binary modification | Persistent access | Backdoored agent |
| **APT / Nation State** | Kernel exploit + patience | Long-term persistence | Full system compromise |

---

## 6. Security Invariants (Formal Properties)

These invariants must hold at ALL times, in ALL code paths:

### 6.1 Action Safety Invariants

```
INVARIANT 1: No Security Regression
  ∀ action A, state S, state S':
    execute(A, S) → S' ⟹ security_posture(S') ≥ security_posture(S)
    
INVARIANT 2: Atomic Commit or Full Rollback
  ∀ action A:
    (commit(A) ∧ success) ∨ (rollback(A) ∧ original_state_restored)
    ¬(partial_commit ∧ partial_rollback)

INVARIANT 3: Audit Completeness
  ∀ action A:
    execute(A) ⟹ audit_log.contains(record(A))
    
INVARIANT 4: Privilege Monotonicity (Decreasing)
  ∀ time t1 < t2:
    privileges(t2) ⊆ privileges(t1)
    (privileges only decrease, never increase after startup)
```

### 6.2 State Machine Invariants

```
INVARIANT 5: Valid State Transitions Only
  ∀ transition (S1 → S2):
    (S1, S2) ∈ valid_transitions
    
INVARIANT 6: Terminal State is Absorbing
  state = Stopped ⟹ ∀ future_state: future_state = Stopped ∨ restart_occurred

INVARIANT 7: Recovery Before Ready
  state = Ready ⟹ recovery_completed = true
```

---

## 7. Incident Response Integration

### 7.1 Security Events That Must Be Logged

| Event | Severity | Required Response |
|-------|----------|-------------------|
| Authentication failure | High | Log + rate limit + alert after N failures |
| Policy violation attempt | High | Log + deny + alert |
| Crash recovery triggered | Medium | Log + notify supervisor |
| Repeated rollback failures | Critical | Log + halt + require human intervention |
| Signature verification failure | Critical | Log + reject + alert |
| Resource exhaustion | Medium | Log + graceful degradation |

### 7.2 Forensic Preservation

The agent must preserve evidence for incident investigation:

- **Immutable audit log**: Hash-chained, cannot be modified after write
- **Crash dumps**: Captured by supervisor, stored securely
- **Command history**: All IPC commands logged with full context
- **State snapshots**: Periodic checkpoints of configuration state

---

## 8. Compliance Mapping

| Requirement | Control | Implementation |
|-------------|---------|----------------|
| **Least Privilege** (NIST AC-6) | Capability dropping, seccomp | `security/privileges.rs`, `security/sandbox.rs` |
| **Audit Logging** (NIST AU-2) | Hash-chained audit logger | `audit/logger.rs`, `audit/sink.rs` |
| **Fail Secure** (NIST SC-24) | Deny-by-default, fail-closed | `security/policy.rs`, all error handlers |
| **Input Validation** (OWASP) | Schema validation, bounds checking | `events/source.rs`, `config/validator.rs` |
| **Cryptographic Integrity** (FIPS 140-2) | Ed25519, BLAKE3 | `security/auth.rs`, `audit/integrity.rs` |

---

## 9. Review and Update Schedule

| Review Type | Frequency | Responsible Party |
|-------------|-----------|-------------------|
| Threat model review | Quarterly | Security Engineering |
| Penetration testing | Annually | External Red Team |
| Code audit | Per major release | Security Engineering |
| Dependency audit | Monthly | DevSecOps |
| Incident-driven update | As needed | Security Engineering |

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **WAL** | Write-Ahead Log; ensures atomic operations |
| **TCB** | Trusted Computing Base; minimal trusted components |
| **Fail-closed** | On error, deny access rather than allow |
| **Compensation** | Rollback action that undoes a previous action |
| **Hash chain** | Sequential hashing linking log entries for tamper detection |

---

## Appendix B: Related Documents

- `README.md` - Architecture overview
- `config/agent.toml.example` - Configuration reference
- `src/security/policy.rs` - Policy engine implementation
- `src/rollback/journal.rs` - WAL implementation
- `src/audit/logger.rs` - Audit logging implementation
