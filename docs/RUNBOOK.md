# WhiteQubit Agent - Production Runbook

**Version:** 1.0  
**Last Updated:** 2026-01-17  
**Status:** Phase 1 Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Systemd Setup](#systemd-setup)
6. [Startup Sequence](#startup-sequence)
7. [Common Failure Modes](#common-failure-modes)
8. [Troubleshooting Guide](#troubleshooting-guide)
9. [Security Considerations](#security-considerations)
10. [Monitoring & Observability](#monitoring--observability)

---

## Overview

WhiteQubit Agent is a security-critical Linux daemon that:
- Monitors SSH authentication failures via journald
- Manages firewall rules via iptables
- Maintains tamper-evident audit logs
- Provides crash recovery via write-ahead logging

### Architecture

```
┌─────────────────────────────────────────┐
│          Application Layer              │
│  (Event Loop, Actions, Audit Logger)    │
├─────────────────────────────────────────┤
│          Seccomp Filter                 │
│  (70+ allowed syscalls, EPERM default)  │
├─────────────────────────────────────────┤
│          Landlock Sandbox               │
│  (RO: /etc, /usr, /lib; RW: /var/...)   │
├─────────────────────────────────────────┤
│          Privilege Drop                 │
│  (setuid/setgid + PR_SET_NO_NEW_PRIVS)  │
├─────────────────────────────────────────┤
│          Linux Kernel                   │
└─────────────────────────────────────────┘
```

---

## Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|------------|---------|-------------|
| Linux Kernel | 5.13+ | 6.1+ |
| RAM | 64 MB | 128 MB |
| Disk | 100 MB | 500 MB |
| CPU | 1 core | 2 cores |

### Kernel Features

The agent requires:

1. **Landlock** (filesystem sandbox) - Kernel 5.13+
   ```bash
   # Check Landlock support
   cat /sys/kernel/security/landlock/abi
   ```

2. **Seccomp** (syscall filtering) - Kernel 3.5+
   ```bash
   # Check seccomp support
   grep CONFIG_SECCOMP /boot/config-$(uname -r)
   ```

### Required Packages

```bash
# Debian/Ubuntu
sudo apt install iptables

# RHEL/CentOS
sudo yum install iptables

# Arch Linux
sudo pacman -S iptables
```

---

## Installation

### 1. Create Service User

```bash
# Create dedicated user and group
sudo groupadd -r whitequbit
sudo useradd -r -g whitequbit -s /sbin/nologin -d /var/lib/whitequbit whitequbit

# Add to systemd-journal group for SSH monitoring
sudo usermod -aG systemd-journal whitequbit
```

### 2. Create Required Directories

```bash
# State directory (WAL, checkpoints)
sudo mkdir -p /var/lib/whitequbit
sudo chown whitequbit:whitequbit /var/lib/whitequbit
sudo chmod 750 /var/lib/whitequbit

# Log directory (audit logs)
sudo mkdir -p /var/log/whitequbit
sudo chown whitequbit:whitequbit /var/log/whitequbit
sudo chmod 750 /var/log/whitequbit

# Runtime directory (PID, socket)
sudo mkdir -p /run/whitequbit
sudo chown whitequbit:whitequbit /run/whitequbit
sudo chmod 750 /run/whitequbit
```

### 3. Install Binary

```bash
# Build from source
cargo build --release

# Install binary
sudo install -m 755 target/release/whitequbit-agent /usr/bin/

# Set capabilities (required for firewall management)
sudo setcap 'cap_net_admin,cap_kill+ep' /usr/bin/whitequbit-agent
```

### 4. Install Configuration

```bash
# Create config directory
sudo mkdir -p /etc/whitequbit

# Install example config
sudo cp config/agent.toml.example /etc/whitequbit/agent.toml
sudo chmod 640 /etc/whitequbit/agent.toml
sudo chown root:whitequbit /etc/whitequbit/agent.toml
```

---

## Configuration

### Configuration File Location

Default: `/etc/whitequbit/agent.toml`

### Minimal Configuration

```toml
# /etc/whitequbit/agent.toml

wal_path = "/var/lib/whitequbit/wal"
audit_path = "/var/log/whitequbit/audit.log"
socket_path = "/run/whitequbit/agent.sock"
pid_path = "/run/whitequbit/agent.pid"

[security]
target_uid = 1001  # UID of whitequbit user
target_gid = 1001  # GID of whitequbit group
drop_privileges = true
apply_sandbox = true
allowed_client_uids = [0]  # Only root can connect

[logging]
level = "info"
format = "json"
file = true
file_path = "/var/log/whitequbit/agent.log"
```

### Security Configuration

```toml
[security]
# User/group to drop privileges to (lookup with: id whitequbit)
target_uid = 1001
target_gid = 1001

# Enable privilege drop (RECOMMENDED: true)
drop_privileges = true

# Enable sandbox (RECOMMENDED: true)
apply_sandbox = true

# Use ambient capabilities (set to false if getting PR_CAP_AMBIENT errors)
use_ambient_caps = false

# IPC client restrictions
allowed_client_uids = [0]       # UIDs allowed to connect
allowed_client_gids = []        # GIDs allowed to connect

[security.sandbox]
enable_seccomp = true
enable_landlock = true

# Paths the agent can read
readonly_paths = [
    "/etc/whitequbit",
    "/usr",
    "/lib",
    "/lib64",
]

# Paths the agent can write
readwrite_paths = [
    "/var/lib/whitequbit",
    "/var/log/whitequbit",
    "/run/whitequbit",
]
```

---

## Systemd Setup

### Service Unit File

Create `/etc/systemd/system/whitequbit-agent.service`:

```ini
[Unit]
Description=WhiteQubit Security Agent
Documentation=https://github.com/your-org/whitequbit-agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/whitequbit-agent --config /etc/whitequbit/agent.toml

# === CRITICAL: Directory Setup ===
# These directives create directories with correct ownership
RuntimeDirectory=whitequbit
StateDirectory=whitequbit
LogsDirectory=whitequbit

# === CRITICAL: Filesystem Access ===
# Required if using ProtectSystem=strict
ReadWritePaths=/var/lib/whitequbit /var/log/whitequbit /run/whitequbit

# Security hardening
NoNewPrivileges=no  # Required for capability handling
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Required capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL
CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_SETUID CAP_SETGID

# Restart policy
Restart=on-failure
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable whitequbit-agent

# Start service
sudo systemctl start whitequbit-agent

# Check status
sudo systemctl status whitequbit-agent
```

---

## Startup Sequence

The agent performs these phases on startup:

| Phase | Description | Potential Failures |
|-------|-------------|-------------------|
| 1 | Parse arguments, load config | Config file missing, parse error |
| 2 | Validate configuration | Invalid values, missing required fields |
| 3 | **Run startup checks** | Directories missing, capabilities missing |
| 4 | Open privileged resources | Permission denied, disk full |
| 5 | Crash recovery from WAL | Corrupted WAL |
| 6 | Initialize audit logger | Write permission denied |
| 7 | Drop privileges | User doesn't exist |
| 8 | Apply sandbox | Kernel doesn't support Landlock/seccomp |
| 9 | Initialize event sources | Journal access denied |
| 10 | Run event loop | - |

### Startup Check Details

The agent validates these at startup:

- ✓ `/var/lib/whitequbit` exists and is writable
- ✓ `/var/log/whitequbit` exists and is writable
- ✓ `/run/whitequbit` exists and is writable
- ✓ `CAP_NET_ADMIN` capability is available
- ✓ `CAP_KILL` capability is available
- ✓ Landlock is supported (kernel 5.13+)
- ✓ Seccomp is supported
- ✓ Target user/group exists
- ✓ iptables binary is available

---

## Common Failure Modes

### 1. Missing Runtime Directories

**Symptom:**
```
Startup check FAILED: Required directory does not exist: /var/lib/whitequbit
```

**Fix:**
```bash
# Manual fix
sudo mkdir -p /var/lib/whitequbit /var/log/whitequbit /run/whitequbit
sudo chown whitequbit:whitequbit /var/lib/whitequbit /var/log/whitequbit /run/whitequbit

# Or add to systemd unit
[Service]
RuntimeDirectory=whitequbit
StateDirectory=whitequbit
LogsDirectory=whitequbit
```

### 2. Read-Only Filesystem (ProtectSystem=strict)

**Symptom:**
```
Cannot write to /var/lib/whitequbit: Read-only file system
```

**Fix:**
Add to systemd unit:
```ini
[Service]
ReadWritePaths=/var/lib/whitequbit /var/log/whitequbit /run/whitequbit
```

### 3. Missing Capabilities

**Symptom:**
```
Startup check FAILED: CAP_NET_ADMIN capability is required
```

**Fix:**
```bash
# Option 1: Set file capabilities
sudo setcap 'cap_net_admin,cap_kill+ep' /usr/bin/whitequbit-agent

# Option 2: Use systemd AmbientCapabilities
[Service]
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL
```

### 4. Landlock Not Supported

**Symptom:**
```
Landlock filesystem sandboxing is not supported on this kernel
```

**Fix Options:**
1. Upgrade kernel to 5.13+
2. Disable Landlock (reduces security):
   ```toml
   [security.sandbox]
   enable_landlock = false
   ```

### 5. Journal Access Denied (SSH Monitoring)

**Symptom:**
```
Cannot read systemd journal - SSH monitoring disabled
```

**Fix:**
```bash
# Add service user to journal group
sudo usermod -aG systemd-journal whitequbit
# Restart service
sudo systemctl restart whitequbit-agent
```

### 6. Target User Doesn't Exist

**Symptom:**
```
Failed to set uid: EINVAL
```

**Fix:**
```bash
# Create the user
sudo useradd -r -s /sbin/nologin whitequbit

# Update config with correct UID
id whitequbit
# Edit /etc/whitequbit/agent.toml with the UID/GID
```

### 7. iptables Not Found

**Symptom:**
```
iptables binary not found. Firewall management will not work.
```

**Fix:**
```bash
# Debian/Ubuntu
sudo apt install iptables

# RHEL/CentOS
sudo yum install iptables
```

### 8. PR_CAP_AMBIENT_RAISE Error

**Symptom:**
```
Failed to raise ambient CAP_NET_ADMIN: EPERM
```

**Fix:**
Disable ambient capabilities in config:
```toml
[security]
use_ambient_caps = false
```

---

## Troubleshooting Guide

### Check Service Status

```bash
# View service status
sudo systemctl status whitequbit-agent

# View recent logs
sudo journalctl -u whitequbit-agent -n 50

# Follow logs in real-time
sudo journalctl -u whitequbit-agent -f
```

### Verify Configuration

```bash
# Check config syntax
whitequbit-agent --config /etc/whitequbit/agent.toml --dry-run
```

### Check Permissions

```bash
# Verify directory ownership
ls -la /var/lib/whitequbit /var/log/whitequbit /run/whitequbit

# Check capabilities on binary
getcap /usr/bin/whitequbit-agent

# Verify user exists
id whitequbit

# Check group membership
groups whitequbit
```

### Check Kernel Support

```bash
# Landlock
cat /sys/kernel/security/landlock/abi

# Seccomp
grep -c CONFIG_SECCOMP=y /boot/config-$(uname -r)

# Kernel version
uname -r
```

### Manual Startup Test

```bash
# Run in foreground for debugging
sudo /usr/bin/whitequbit-agent --config /etc/whitequbit/agent.toml --foreground

# Run with debug logging
RUST_LOG=debug sudo /usr/bin/whitequbit-agent --config /etc/whitequbit/agent.toml --foreground
```

---

## Security Considerations

### Principle of Least Privilege

1. **Run as non-root**: Agent drops to dedicated user after startup
2. **Minimal capabilities**: Only CAP_NET_ADMIN and CAP_KILL retained
3. **Filesystem sandbox**: Landlock restricts file access
4. **Syscall filter**: Seccomp allows only necessary syscalls

### Audit Trail

- All actions logged to `/var/log/whitequbit/audit.log`
- Hash-chain integrity (tamper detection)
- Includes: timestamp, action, actor, outcome

### Crash Recovery

- Write-ahead log at `/var/lib/whitequbit/wal`
- Uncommitted actions replayed on restart
- Prevents "orphaned" firewall rules

---

## Monitoring & Observability

### Log Files

| File | Purpose |
|------|---------|
| `/var/log/whitequbit/agent.log` | Application logs |
| `/var/log/whitequbit/audit.log` | Security audit trail |
| `/var/lib/whitequbit/wal` | Write-ahead log |

### Health Checks

```bash
# Check if socket is listening
ls -la /run/whitequbit/agent.sock

# Check PID file
cat /run/whitequbit/agent.pid

# Check process is running
pgrep -f whitequbit-agent
```

### Metrics (Future)

Phase 2 will add Prometheus metrics endpoint.

---

## Quick Reference

### Required systemd Directives

```ini
RuntimeDirectory=whitequbit
StateDirectory=whitequbit
LogsDirectory=whitequbit
ReadWritePaths=/var/lib/whitequbit /var/log/whitequbit /run/whitequbit
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL
```

### Required Directories

```
/var/lib/whitequbit   - State (WAL, checkpoints)
/var/log/whitequbit   - Logs (audit, application)
/run/whitequbit       - Runtime (PID, socket)
/etc/whitequbit       - Configuration
```

### Required Capabilities

```
CAP_NET_ADMIN - Firewall management (iptables)
CAP_KILL      - Service management (kill signals)
```

### Emergency Stop

```bash
# Graceful shutdown
sudo systemctl stop whitequbit-agent

# Force stop
sudo systemctl kill -s SIGKILL whitequbit-agent

# Clear WAL (if corrupted)
sudo rm /var/lib/whitequbit/wal
```

---

*Document Version: 1.0 | Phase 1 Complete*
