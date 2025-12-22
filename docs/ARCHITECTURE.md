# WhiteQubit Agent - System Architecture

**Document Version:** 1.0  
**Last Updated:** 2025-12-22  
**Classification:** Engineering Architecture Documentation

---

## 1. Overview

WhiteQubit Agent is a production-grade system daemon that executes security actions with guaranteed reversibility, crash safety, and complete audit trails. It operates under strict security constraints with minimal privileges.

### 1.1 Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Continuous Operation** | Event-driven async runtime; no polling; graceful degradation |
| **Reversible Actions** | Write-Ahead Log (WAL) with compensation handlers |
| **Crash Safety** | Atomic state transitions; recovery on startup |
| **Immutable Audit** | Hash-chained log entries; append-only storage |
| **Least Privilege** | Capability dropping; seccomp/Landlock sandboxing |
| **Event-Driven** | Async channels; signal handlers; IPC listeners |

---

## 2. Module Layout

```
whitequbit-agent/
├── src/
│   ├── main.rs                 # Daemon entry point, startup sequence
│   ├── supervisor_main.rs      # Watchdog supervisor entry point
│   ├── lib.rs                  # Library root, module exports
│   │
│   ├── core/                   # Core daemon infrastructure
│   │   ├── mod.rs              # State machine, core errors
│   │   ├── event_loop.rs       # Main async event reactor
│   │   ├── state_machine.rs    # Agent state transitions
│   │   ├── shutdown.rs         # Graceful shutdown coordination
│   │   └── supervisor.rs       # Supervisor communication
│   │
│   ├── events/                 # Event ingestion & dispatch
│   │   ├── mod.rs              # Event types, errors
│   │   ├── source.rs           # Event definitions & sources
│   │   ├── dispatcher.rs       # Event routing & queuing
│   │   ├── signals.rs          # OS signal handling
│   │   └── ipc.rs              # IPC socket listener
│   │
│   ├── actions/                # Security action execution
│   │   ├── mod.rs              # Action trait, errors
│   │   ├── action.rs           # Action trait definition
│   │   ├── executor.rs         # Sandboxed action executor
│   │   ├── registry.rs         # Action type registry
│   │   ├── firewall.rs         # Firewall rule actions
│   │   └── services.rs         # Service management actions
│   │
│   ├── rollback/               # Crash recovery & rollback
│   │   ├── mod.rs              # Rollback errors
│   │   ├── journal.rs          # Write-Ahead Log (WAL)
│   │   ├── checkpoint.rs       # State checkpointing
│   │   ├── compensator.rs      # Compensation action execution
│   │   └── recovery.rs         # Startup recovery logic
│   │
│   ├── audit/                  # Immutable audit logging
│   │   ├── mod.rs              # Audit types, errors
│   │   ├── logger.rs           # Hash-chained audit logger
│   │   ├── integrity.rs        # Integrity verification
│   │   └── sink.rs             # Output sinks (file, syslog)
│   │
│   ├── security/               # Security subsystems
│   │   ├── mod.rs              # Security errors
│   │   ├── auth.rs             # Command authentication
│   │   ├── policy.rs           # Policy engine
│   │   ├── privileges.rs       # Privilege management
│   │   └── sandbox.rs          # seccomp/Landlock sandbox
│   │
│   ├── config/                 # Configuration management
│   │   ├── mod.rs              # Config types
│   │   ├── loader.rs           # Config file loading
│   │   └── validator.rs        # Config validation
│   │
│   └── observability/          # Metrics & health
│       ├── mod.rs              # Module exports
│       ├── metrics.rs          # Runtime metrics
│       └── health.rs           # Health check system
│
├── config/
│   └── agent.toml.example      # Configuration template
│
├── systemd/
│   └── whitequbit-agent.service # Systemd unit file
│
└── docs/
    ├── ARCHITECTURE.md         # This document
    └── THREAT_MODEL.md         # Security threat model
```

### 2.1 Module Responsibilities

| Module | Responsibility | Dependencies |
|--------|---------------|--------------|
| `core` | Lifecycle management, state machine, event loop | All modules |
| `events` | Event ingestion, routing, signal handling | `actions`, `audit` |
| `actions` | Action execution, sandboxing, registry | `rollback`, `audit`, `security` |
| `rollback` | WAL, checkpoints, recovery, compensation | `audit` |
| `audit` | Immutable logging, integrity verification | None (leaf module) |
| `security` | Auth, policy, privileges, sandboxing | `config` |
| `config` | Configuration loading and validation | None (leaf module) |
| `observability` | Metrics collection, health checks | None (leaf module) |

---

## 3. Data Flow Between Modules

### 3.1 High-Level Data Flow

```
                                    ┌─────────────────┐
                                    │   OS Signals    │
                                    │ (SIGTERM, HUP)  │
                                    └────────┬────────┘
                                             │
┌─────────────────┐                          ▼
│   IPC Socket    │                 ┌─────────────────┐
│  (Commands)     │────────────────▶│     events/     │
└─────────────────┘                 │   dispatcher    │
                                    └────────┬────────┘
┌─────────────────┐                          │
│  Event Sources  │                          │
│ (File watches,  │──────────────────────────┘
│  Network, etc.) │                          │
└─────────────────┘                          ▼
                                    ┌─────────────────┐
                                    │   security/     │
                                    │     policy      │◄──────┐
                                    └────────┬────────┘       │
                                             │                │
                              ┌──────────────┼──────────────┐ │
                              │ DENY         │ ALLOW        │ │
                              ▼              ▼              │ │
                    ┌─────────────┐  ┌─────────────────┐    │ │
                    │   audit/    │  │    rollback/    │    │ │
                    │   logger    │  │     journal     │    │ │
                    │  (rejected) │  │   (WAL write)   │    │ │
                    └─────────────┘  └────────┬────────┘    │ │
                                              │             │ │
                                              ▼             │ │
                                    ┌─────────────────┐     │ │
                                    │    actions/     │     │ │
                                    │    executor     │     │ │
                                    │   (sandboxed)   │     │ │
                                    └────────┬────────┘     │ │
                                              │             │ │
                              ┌───────────────┼─────────────┘ │
                              │               │               │
                              ▼               ▼               │
                    ┌─────────────┐  ┌─────────────────┐      │
                    │  FAILURE    │  │    SUCCESS      │      │
                    │  Rollback   │  │  Commit WAL     │      │
                    │  via WAL    │  │  Log to Audit   │      │
                    └─────────────┘  └─────────────────┘      │
                              │               │               │
                              └───────────────┴───────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │  observability/ │
                                    │    metrics      │
                                    └─────────────────┘
```

### 3.2 Inter-Module Communication

| From | To | Mechanism | Data |
|------|-----|-----------|------|
| `events/dispatcher` | `core/event_loop` | Async channel | `Event` structs |
| `events/signals` | `core/event_loop` | Broadcast channel | `Signal` enum |
| `core/event_loop` | `security/policy` | Direct call | `Event` for authorization |
| `security/policy` | `actions/executor` | Direct call | Authorized `Action` |
| `actions/executor` | `rollback/journal` | Direct call | WAL entries |
| `actions/executor` | `audit/logger` | Direct call | Audit entries |
| `core/shutdown` | All modules | Watch channel | Shutdown phase |
| `observability/health` | `core/event_loop` | Polling interval | Health status |

---

## 4. Action Lifecycle

### 4.1 Complete Action Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ACTION LIFECYCLE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 1: REQUEST                                                     │   │
│  │                                                                       │   │
│  │  1. Event received via IPC/signal                                    │   │
│  │  2. Input validation (schema, bounds, sanitization)                  │   │
│  │  3. Authentication verification (signature check)                    │   │
│  │  4. Authorization check (policy engine)                              │   │
│  │  5. Rate limiting enforcement                                        │   │
│  │                                                                       │   │
│  │  Output: Authorized Action or Rejection                              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 2: PREPARE                                                     │   │
│  │                                                                       │   │
│  │  1. Generate unique Action ID (UUID v7 for time-ordering)           │   │
│  │  2. Capture pre-execution state (for rollback)                       │   │
│  │  3. Build compensation handler (rollback procedure)                  │   │
│  │  4. Write WAL entry: { action, pre_state, compensation, PREPARED }   │   │
│  │  5. Sync WAL to disk (fsync)                                         │   │
│  │                                                                       │   │
│  │  CRASH HERE → Recovery will skip this action (not committed)         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 3: APPLY                                                       │   │
│  │                                                                       │   │
│  │  1. Enter sandbox (seccomp/Landlock restrictions)                    │   │
│  │  2. Execute action (firewall rule, service command, etc.)            │   │
│  │  3. Capture execution result and any side effects                    │   │
│  │  4. Update WAL entry: { ..., APPLIED, result }                       │   │
│  │                                                                       │   │
│  │  CRASH HERE → Recovery will execute compensation (rollback)          │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 4: VERIFY                                                      │   │
│  │                                                                       │   │
│  │  1. Verify action took effect (read back state)                      │   │
│  │  2. Validate post-conditions                                         │   │
│  │  3. Check for conflicts with other rules/state                       │   │
│  │  4. Update WAL entry: { ..., VERIFIED } or { ..., VERIFY_FAILED }    │   │
│  │                                                                       │   │
│  │  VERIFY_FAILED → Automatic rollback triggered                        │   │
│  │  CRASH HERE → Recovery will verify and decide                        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 5: COMMIT                                                      │   │
│  │                                                                       │   │
│  │  1. Update WAL entry: { ..., COMMITTED }                             │   │
│  │  2. Sync WAL (fsync) - POINT OF NO AUTOMATIC RETURN                  │   │
│  │  3. Write immutable audit log entry                                  │   │
│  │  4. Update metrics (success counter)                                 │   │
│  │  5. Send acknowledgment to requester                                 │   │
│  │  6. Mark WAL entry as complete (can be garbage collected)            │   │
│  │                                                                       │   │
│  │  CRASH HERE → Recovery confirms committed, no rollback               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Action States

```
                    ┌─────────────┐
                    │   PENDING   │ (in event queue)
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
           ┌────────│  PREPARED   │ (WAL written, not executed)
           │        └──────┬──────┘
           │               │
           │               ▼
           │        ┌─────────────┐
           │   ┌────│   APPLIED   │ (executed, not verified)
           │   │    └──────┬──────┘
           │   │           │
           │   │           ▼
           │   │    ┌─────────────┐
           │   │    │  VERIFIED   │ (confirmed working)
           │   │    └──────┬──────┘
           │   │           │
           │   │           ▼
           │   │    ┌─────────────┐
           │   │    │  COMMITTED  │ (final, in audit log)
           │   │    └─────────────┘
           │   │
           │   │    ┌─────────────┐
           │   └───▶│   FAILED    │ (execution failed)
           │        └──────┬──────┘
           │               │
           ▼               ▼
    ┌─────────────────────────────┐
    │        ROLLED_BACK          │ (compensation executed)
    └─────────────────────────────┘
```

---

## 5. Rollback Lifecycle

### 5.1 Rollback Trigger Points

| Trigger | Condition | Response |
|---------|-----------|----------|
| **Execution failure** | Action returns error | Immediate rollback |
| **Verification failure** | Post-condition check fails | Immediate rollback |
| **Explicit request** | Rollback command received | Validated rollback |
| **Crash recovery** | APPLIED but not COMMITTED in WAL | Automatic rollback |
| **Timeout** | Action exceeds time limit | Forced rollback |
| **Policy violation** | Late policy check fails | Immediate rollback |

### 5.2 Rollback Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ROLLBACK LIFECYCLE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 1: IDENTIFY ROLLBACK TARGET                                     │   │
│  │                                                                       │   │
│  │  • Load WAL entry for target action                                  │   │
│  │  • Verify action is in rollback-eligible state                       │   │
│  │  • Extract stored pre-state and compensation handler                 │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 2: PREPARE COMPENSATION                                         │   │
│  │                                                                       │   │
│  │  • Mark WAL entry as ROLLING_BACK                                    │   │
│  │  • Sync WAL to disk                                                  │   │
│  │  • Validate compensation handler is still valid                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 3: EXECUTE COMPENSATION                                         │   │
│  │                                                                       │   │
│  │  • Enter sandbox (same restrictions as original action)              │   │
│  │  • Execute compensation handler                                      │   │
│  │  • Restore pre-state captured during PREPARE phase                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                          ┌──────────┴──────────┐                            │
│                          ▼                     ▼                            │
│                    ┌───────────┐         ┌───────────┐                      │
│                    │  SUCCESS  │         │  FAILURE  │                      │
│                    └─────┬─────┘         └─────┬─────┘                      │
│                          │                     │                            │
│                          ▼                     ▼                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ STEP 4A: ROLLBACK SUCCESS          │ STEP 4B: ROLLBACK FAILURE       │   │
│  │                                     │                                 │   │
│  │  • Mark WAL: ROLLED_BACK           │  • Mark WAL: ROLLBACK_FAILED   │   │
│  │  • Log to audit (rollback event)   │  • CRITICAL ALERT              │   │
│  │  • Update metrics                   │  • Require human intervention  │   │
│  │  • WAL entry eligible for GC        │  • Preserve all state for      │   │
│  │                                     │    forensic analysis           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Compensation Strategies by Action Type

| Action Type | Compensation Strategy | Idempotency |
|-------------|----------------------|-------------|
| **Add firewall rule** | Remove the added rule | ✓ Safe to retry |
| **Remove firewall rule** | Re-add the rule (from saved state) | ✓ Safe to retry |
| **Stop service** | Start service | ⚠ Check if already running |
| **Start service** | Stop service | ⚠ Check if was running before |
| **Restart service** | No-op (already restarted) | ✓ No compensation needed |
| **Block IP** | Unblock IP | ✓ Safe to retry |

---

## 6. Startup Sequence

### 6.1 Startup Phases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           STARTUP SEQUENCE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 1: INITIALIZATION (Running as root)                                 │
│  ═══════════════════════════════════════════                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  1.1  Parse command-line arguments                                   │   │
│  │  1.2  Load and validate configuration file                          │   │
│  │  1.3  Verify configuration signature (if required)                  │   │
│  │  1.4  Initialize state machine in INIT state                        │   │
│  │  1.5  Set up panic handler for crash reporting                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  PHASE 2: PRIVILEGED RESOURCE ACQUISITION                                  │
│  ═════════════════════════════════════════                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  2.1  Open/create PID file (exclusive lock)                         │   │
│  │  2.2  Open audit log file                                           │   │
│  │  2.3  Open WAL journal file                                         │   │
│  │  2.4  Create IPC socket with restrictive permissions                │   │
│  │  2.5  Bind to any required network ports                            │   │
│  │                                                                       │   │
│  │  ★ All privileged file descriptors opened here                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  PHASE 3: CRASH RECOVERY (State: RECOVERING)                               │
│  ═══════════════════════════════════════════                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  3.1  Transition state machine to RECOVERING                        │   │
│  │  3.2  Scan WAL for uncommitted entries                              │   │
│  │  3.3  For each uncommitted entry:                                   │   │
│  │       ├─ PREPARED: Skip (was never executed)                        │   │
│  │       ├─ APPLIED:  Execute compensation (rollback)                  │   │
│  │       ├─ VERIFIED: Mark as COMMITTED (safe to keep)                 │   │
│  │       └─ ROLLING_BACK: Retry compensation                           │   │
│  │  3.4  Compact WAL (remove completed entries)                        │   │
│  │  3.5  Verify audit log integrity (check hash chain)                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  PHASE 4: PRIVILEGE REDUCTION                                              │
│  ═══════════════════════════════                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  4.1  Switch to unprivileged user/group                             │   │
│  │  4.2  Drop all capabilities except required set                     │   │
│  │  4.3  Set NO_NEW_PRIVS flag                                         │   │
│  │  4.4  Apply seccomp BPF filter                                      │   │
│  │  4.5  Apply Landlock filesystem restrictions                        │   │
│  │                                                                       │   │
│  │  ★ POINT OF NO RETURN: Cannot regain privileges                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  PHASE 5: SERVICE INITIALIZATION                                           │
│  ═══════════════════════════════════                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  5.1  Initialize audit logger (start hash chain)                    │   │
│  │  5.2  Initialize metrics subsystem                                  │   │
│  │  5.3  Start signal handler (SIGTERM, SIGHUP, etc.)                  │   │
│  │  5.4  Initialize event dispatcher                                   │   │
│  │  5.5  Start IPC listener                                            │   │
│  │  5.6  Log startup complete to audit log                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  PHASE 6: READY (State: READY)                                             │
│  ═════════════════════════════                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  6.1  Transition state machine to READY                             │   │
│  │  6.2  Notify supervisor (if running under supervision)              │   │
│  │  6.3  Enter main event loop                                         │   │
│  │  6.4  Begin accepting and processing events                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Startup Failure Handling

| Failure Point | Action | Exit Code |
|---------------|--------|-----------|
| Invalid configuration | Log error, exit | 1 |
| PID file locked | Already running, exit | 2 |
| Cannot open privileged resources | Log error, exit | 3 |
| WAL corruption | Enter safe mode, require human | 4 |
| Crash recovery failure | Enter safe mode, require human | 5 |
| Privilege drop failure | Log error, exit | 6 |
| Sandbox setup failure | Log error, exit | 7 |

---

## 7. Shutdown Sequence

### 7.1 Shutdown Phases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SHUTDOWN SEQUENCE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TRIGGER: SIGTERM received or shutdown command via IPC                     │
│                                                                             │
│  PHASE 1: STOP ACCEPTING (State: DRAINING)                                 │
│  ═════════════════════════════════════════                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  1.1  Transition state machine to DRAINING                          │   │
│  │  1.2  Close IPC listener (reject new connections)                   │   │
│  │  1.3  Stop accepting new events                                     │   │
│  │  1.4  Notify supervisor of impending shutdown                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  PHASE 2: DRAIN IN-FLIGHT WORK                                             │
│  ═════════════════════════════════                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  2.1  Wait for in-flight actions to complete (with timeout)         │   │
│  │  2.2  For each action past timeout:                                 │   │
│  │       ├─ If APPLIED: Force rollback                                 │   │
│  │       └─ If VERIFIED: Force commit                                  │   │
│  │  2.3  Drain event queue (log dropped events)                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  PHASE 3: PERSIST STATE                                                    │
│  ══════════════════════                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  3.1  Flush WAL to disk (fsync)                                     │   │
│  │  3.2  Flush audit log to disk                                       │   │
│  │  3.3  Write final checkpoint                                        │   │
│  │  3.4  Log shutdown event to audit log                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│  PHASE 4: CLEANUP (State: STOPPED)                                         │
│  ═════════════════════════════════                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  4.1  Transition state machine to STOPPED                           │   │
│  │  4.2  Close all file descriptors                                    │   │
│  │  4.3  Remove PID file                                               │   │
│  │  4.4  Exit with code 0                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      IMMEDIATE SHUTDOWN (SIGKILL/Crash)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  • No graceful shutdown possible                                           │
│  • WAL preserves all in-flight state                                       │
│  • Recovery on next startup will handle incomplete actions                 │
│  • Supervisor will detect termination and may restart                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Shutdown Timeouts

| Phase | Default Timeout | On Timeout |
|-------|-----------------|------------|
| Drain in-flight actions | 30 seconds | Force rollback/commit |
| WAL flush | 5 seconds | Log warning, continue |
| Audit flush | 5 seconds | Log warning, continue |
| Total shutdown | 60 seconds | SIGKILL from supervisor |

---

## 8. Crash Recovery Strategy

### 8.1 WAL-Based Recovery

The Write-Ahead Log (WAL) ensures that the system can recover to a consistent state after any crash:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CRASH RECOVERY DECISION TREE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  On startup, scan WAL for entries not in terminal state:                   │
│                                                                             │
│  WAL Entry State          │  Recovery Action                               │
│  ═════════════════════════╪═══════════════════════════════════════════════ │
│                           │                                                 │
│  PREPARED                 │  Action was never executed                     │
│  ├─ Safe to skip          │  → Mark as SKIPPED                             │
│  └─ No system changes     │  → Log to audit as "abandoned"                 │
│                           │                                                 │
│  APPLIED                  │  Action executed but not verified              │
│  ├─ System may be changed │  → Execute compensation (rollback)             │
│  └─ Must undo             │  → Mark as ROLLED_BACK                         │
│                           │                                                 │
│  VERIFIED                 │  Action verified but not committed             │
│  ├─ System is in new state│  → Safe to commit                              │
│  └─ Commit is safe        │  → Mark as COMMITTED                           │
│                           │                                                 │
│  ROLLING_BACK             │  Rollback was interrupted                      │
│  ├─ Compensation started  │  → Retry compensation                          │
│  └─ Must complete         │  → Mark as ROLLED_BACK or ROLLBACK_FAILED      │
│                           │                                                 │
│  COMMITTED                │  Complete, no action needed                    │
│  └─ Already done          │  → Mark eligible for WAL compaction            │
│                           │                                                 │
│  ROLLED_BACK              │  Complete, no action needed                    │
│  └─ Already done          │  → Mark eligible for WAL compaction            │
│                           │                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Recovery Ordering

When multiple incomplete entries exist in WAL:

1. **Sort by sequence number** (time order)
2. **Process in reverse order for rollbacks** (undo most recent first)
3. **Process in forward order for commits** (preserve causality)

### 8.3 Crash Loop Prevention

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CRASH LOOP DETECTION                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Supervisor tracks restart count:                                          │
│                                                                             │
│  Restarts in 5 min  │  Action                                              │
│  ═══════════════════╪════════════════════════════════════════════════════  │
│  1-2                │  Normal restart, no delay                            │
│  3-4                │  Restart with 5 second delay                         │
│  5-6                │  Restart with 30 second delay                        │
│  7+                 │  Enter SAFE MODE, require human intervention         │
│                                                                             │
│  SAFE MODE:                                                                 │
│  • Agent starts but does not accept commands                               │
│  • WAL recovery is skipped (may contain crash-causing entry)               │
│  • Requires explicit unlock command from administrator                     │
│  • All events are logged but not processed                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.4 WAL Integrity Verification

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       WAL INTEGRITY CHECK                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Each WAL entry contains:                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • Sequence number (monotonic)                                       │   │
│  │  • Entry hash (BLAKE3)                                              │   │
│  │  • Previous entry hash (chain)                                      │   │
│  │  • CRC32 for quick corruption detection                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  On recovery:                                                              │
│  1. Verify CRC32 of each entry                                            │
│  2. Verify hash chain continuity                                          │
│  3. If corruption detected:                                               │
│     ├─ Truncate WAL at last valid entry                                   │
│     ├─ Log corruption event                                               │
│     └─ Alert administrator                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. State Machine Definition

### 9.1 Agent States

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         STATE MACHINE                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                    ┌──────────┐                                            │
│                    │   INIT   │ Starting up, loading config                │
│                    └────┬─────┘                                            │
│                         │                                                   │
│           ┌─────────────┴─────────────┐                                    │
│           ▼                           ▼                                    │
│     ┌───────────┐              ┌───────────┐                               │
│     │RECOVERING │              │ SAFE_MODE │ Crash loop detected           │
│     └─────┬─────┘              └───────────┘                               │
│           │                          ▲                                      │
│           ▼                          │ (crash loop)                        │
│     ┌───────────┐                    │                                     │
│     │   READY   │ ◄─────────────────┬┘                                     │
│     └─────┬─────┘                   │                                      │
│           │                          │                                      │
│           ▼                          │                                      │
│     ┌───────────┐                    │                                     │
│     │ DRAINING  │ Graceful shutdown  │                                     │
│     └─────┬─────┘                    │                                      │
│           │                          │                                      │
│           ▼                          │                                      │
│     ┌───────────┐                    │                                     │
│     │  STOPPED  │ ───────────────────┘ (restart)                           │
│     └───────────┘                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 Valid State Transitions

| From State | To State | Trigger |
|------------|----------|---------|
| INIT | RECOVERING | Startup with WAL entries |
| INIT | READY | Startup with clean WAL |
| INIT | SAFE_MODE | Crash loop detected |
| RECOVERING | READY | Recovery complete |
| RECOVERING | SAFE_MODE | Recovery failed |
| READY | DRAINING | Shutdown signal |
| DRAINING | STOPPED | Drain complete |
| SAFE_MODE | READY | Admin unlock |
| Any | STOPPED | Emergency stop |

---

## 10. Supervisor Architecture

### 10.1 Supervisor Responsibilities

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SUPERVISOR PROCESS                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  HEARTBEAT MONITOR                                                   │   │
│  │  • Agent sends heartbeat every 10 seconds                           │   │
│  │  • If 3 heartbeats missed → Agent considered dead                   │   │
│  │  • Supervisor sends SIGTERM, waits 30s, then SIGKILL                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  RESTART MANAGER                                                     │   │
│  │  • Tracks restart count with exponential backoff                    │   │
│  │  • Resets count after 5 minutes of stability                        │   │
│  │  • Enters safe mode after too many restarts                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  CRASH REPORTER                                                      │   │
│  │  • Captures agent stderr on crash                                   │   │
│  │  • Saves crash dumps for analysis                                   │   │
│  │  • Sends alerts on repeated failures                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  RESOURCE MONITOR                                                    │   │
│  │  • Monitors agent memory/CPU usage                                  │   │
│  │  • Kills agent if resource limits exceeded                          │   │
│  │  • Logs resource warnings                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Appendix A: Configuration Structure

```toml
[agent]
instance_id = "prod-agent-001"
log_level = "info"

[paths]
wal_dir = "/var/lib/whitequbit/wal"
audit_log = "/var/log/whitequbit/audit.log"
pid_file = "/var/run/whitequbit/agent.pid"
socket_path = "/var/run/whitequbit/agent.sock"

[security]
drop_privileges = true
target_user = "whitequbit"
target_group = "whitequbit"
enable_sandbox = true

[policy]
default_action = "deny"
max_actions_per_minute = 100
rule_expiry_hours = 24

[recovery]
max_wal_size_mb = 100
checkpoint_interval_secs = 300
max_recovery_attempts = 3

[supervisor]
heartbeat_interval_secs = 10
max_restart_count = 5
restart_window_secs = 300
```

---

## Appendix B: Related Documents

| Document | Purpose |
|----------|---------|
| `THREAT_MODEL.md` | Security threat analysis and mitigations |
| `README.md` | Quick start and feature overview |
| `config/agent.toml.example` | Configuration reference |
