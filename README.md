# WhiteQubit Agent

A production-grade, secure daemon for executing system-level security actions with full rollback support, immutable audit logging, and comprehensive observability.

## Features

- **Event-Driven Architecture**: Non-blocking, async event loop using Tokio
- **Rollback Support**: Write-Ahead Logging (WAL) ensures every action can be reversed
- **Immutable Audit Logging**: Hash-chained entries for tamper-evident audit trails
- **Crash Resilience**: Automatic recovery on startup, no unsafe intermediate states
- **Privilege Separation**: Drops privileges after startup, retains only required capabilities
- **Sandboxed Execution**: seccomp and Landlock isolation for action execution (Linux)
- **Graceful Shutdown**: Coordinated shutdown with in-flight action completion
- **Observability**: Built-in metrics, health checks, and structured logging

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          WhiteQubit Agent Daemon                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Events    │  │    Core     │  │   Actions   │  │      Security       │ │
│  │  IPC/Signals│──│ Event Loop  │──│  Executor   │──│  Sandbox/Privileges │ │
│  │  Sources    │  │State Machine│  │ Firewall    │  │  Policy Engine      │ │
│  └─────────────┘  │  Shutdown   │  │ Services    │  └─────────────────────┘ │
│         │         │ Coordinator │  │ Registry    │            │             │
│         │         └─────────────┘  └─────────────┘            │             │
│         │                │                │                   │             │
│         │                ▼                ▼                   │             │
│         │         ┌─────────────┐  ┌─────────────┐            │             │
│         │         │  Rollback   │  │Observability│            │             │
│         │         │   Journal   │  │   Metrics   │            │             │
│         │         │ Checkpoint  │  │   Health    │            │             │
│         │         │ Compensator │  │   Checks    │            │             │
│         │         └─────────────┘  └─────────────┘            │             │
│         │                │                                    │             │
│         ▼                ▼                                    │             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                           Audit Logger                                  ││
│  │                    (Hash-Chain Integrity, Multiple Sinks)               ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        WhiteQubit Supervisor                                │
│                    (Watchdog/Heartbeat Monitor)                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Startup Phases

1. **Parse arguments and load configuration** - Validate settings before proceeding
2. **Initialize state machine** - Begin in `Init` state
3. **Open privileged resources** - Files, sockets, PID file
4. **Crash recovery** - Process uncommitted WAL entries
5. **Initialize audit logging** - Start hash-chain logger
6. **Drop privileges** - Switch to unprivileged user (Unix)
7. **Apply sandbox** - seccomp/Landlock restrictions (Linux)
8. **Start signal handler** - Handle SIGTERM, SIGHUP, etc.
9. **Initialize event dispatcher** - Begin accepting events
10. **Enter main event loop** - Process events until shutdown

### State Machine

```
Init ──► Recovering ──► Ready ──► Draining ──► Stopped
  │                       │                       ▲
  └───────────────────────┼───────────────────────┘
        (emergency stop from any state)
```

## Building

```bash
cargo build --release
```

## Installation

```bash
# Create directories
sudo mkdir -p /var/lib/whitequbit /var/log/whitequbit /var/run/whitequbit /etc/whitequbit

# Copy configuration
sudo cp config/agent.toml.example /etc/whitequbit/agent.toml

# Install binaries
sudo cp target/release/whitequbit-agent /usr/local/bin/
sudo cp target/release/whitequbit-supervisor /usr/local/bin/

# Set permissions
sudo chown root:root /usr/local/bin/whitequbit-*
sudo chmod 755 /usr/local/bin/whitequbit-*
```

## Usage

### Starting the Agent

```bash
# Start with default configuration
sudo /usr/local/bin/whitequbit-agent

# Start with custom configuration
sudo /usr/local/bin/whitequbit-agent -c /etc/whitequbit/agent.toml

# Start in foreground mode
sudo /usr/local/bin/whitequbit-agent -f

# Dry run mode (don't execute actions)
sudo /usr/local/bin/whitequbit-agent -n
```

### Starting the Supervisor

The supervisor acts as a watchdog, monitoring the agent and restarting it if it crashes:

```bash
sudo /usr/local/bin/whitequbit-supervisor
```

### Signals

- `SIGTERM`: Graceful shutdown with action completion
- `SIGINT`: Graceful shutdown (same as SIGTERM)
- `SIGHUP`: Reload configuration
- `SIGUSR1`: Reserved for supervisor communication
- `SIGUSR2`: Reserved for future use

## Configuration

See `config/agent.toml.example` for a complete configuration reference.

### Key Configuration Sections

| Section | Description |
|---------|-------------|
| `security` | Privilege dropping, sandbox settings, allowed clients |
| `logging` | Log level, format, rotation |
| `events` | Queue size, rate limiting, timeouts |
| `actions` | Execution timeouts, concurrency limits |
| `rollback` | WAL settings, checkpoint configuration |

## Security Model

### Privilege Dropping

The agent starts as root to:
1. Bind to privileged socket paths
2. Configure firewall rules
3. Manage system services

After initialization, it drops to an unprivileged user while retaining only:
- `CAP_NET_ADMIN` - For firewall management
- `CAP_SYS_PTRACE` - For sandbox enforcement (if needed)

### Sandbox

Actions execute in isolated environments using:
- **seccomp-bpf**: System call filtering
- **Landlock**: Filesystem access control

### Authentication

Clients are authenticated via:
- Unix socket peer credentials (UID/GID)
- TLS client certificates (for remote connections)
- Token-based auth (for API access)

### Authorization

Role-based policy engine with verbs:
- `execute`: Execute actions
- `rollback`: Trigger rollbacks
- `read`: Read state and logs
- `admin`: Administrative operations

## Rollback Mechanism

### Write-Ahead Logging

Every action is journaled before execution:

1. Action received and validated
2. Compensation data computed
3. Entry written to WAL and synced
4. Action executed
5. Success/failure recorded
6. Periodic checkpoints created

### Crash Recovery

On startup:
1. Load latest checkpoint (if exists)
2. Replay uncommitted WAL entries
3. Compensate failed actions (LIFO order)
4. Resume normal operation

## Audit Trail

All events are logged with:
- Timestamp (UTC)
- Event type and severity
- Action details
- Actor information
- Hash chain linking to previous entry

### Integrity Verification

```bash
# Verify audit log integrity
whitequbit-agent --verify-audit /var/log/whitequbit/audit.log
```

## Development

### Running Tests

```bash
cargo test
```

### Code Coverage

```bash
cargo tarpaulin --out Html
```

### Linting

```bash
cargo clippy -- -D warnings
```

## License

Copyright (c) 2024. All rights reserved.
