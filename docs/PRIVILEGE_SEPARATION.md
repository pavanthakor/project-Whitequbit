# Privilege Separation Design

## Overview

The whitequbit-agent implements a **privilege-separated architecture** to minimize the attack surface while still performing privileged security operations. This document details the design, implementation, and security considerations.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ELEVATED STARTUP PHASE                             │
│  (root/SYSTEM - brief, discards after initialization)                       │
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ Open Privileged │  │ Load Sensitive  │  │ Bind to Privileged Ports   │  │
│  │ Files (WAL, etc)│  │ Config/Secrets  │  │ Open Raw Sockets           │  │
│  └────────┬────────┘  └────────┬────────┘  └──────────────┬──────────────┘  │
│           │                    │                          │                  │
│           └────────────────────┼──────────────────────────┘                  │
│                                ▼                                             │
│                    ┌───────────────────────┐                                 │
│                    │   DROP PRIVILEGES     │                                 │
│                    │   - setuid/setgid     │                                 │
│                    │   - setgroups([])     │                                 │
│                    │   - Retain CAPs only  │                                 │
│                    │   - PR_SET_NO_NEW_PRIVS│                                │
│                    └───────────┬───────────┘                                 │
└────────────────────────────────┼─────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        UNPRIVILEGED MAIN PROCESS                             │
│  (whitequbit user, sandboxed, seccomp filtered)                             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         EVENT LOOP                                   │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │   IPC Rx    │  │  Signal Rx  │  │  Timer Rx   │  │ Action Rx  │  │    │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘  │    │
│  │         └────────────────┼───────────────┬───────────────┘          │    │
│  │                          ▼               │                          │    │
│  │                ┌─────────────────────────┴──────┐                   │    │
│  │                │     ACTION DISPATCHER          │                   │    │
│  │                │  - Validate action             │                   │    │
│  │                │  - Check policy                │                   │    │
│  │                │  - WAL write (pre-commit)      │                   │    │
│  │                └───────────────┬────────────────┘                   │    │
│  └────────────────────────────────┼────────────────────────────────────┘    │
│                                   │                                          │
│                                   ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    PRIVILEGED ACTION EXECUTOR                        │    │
│  │  (fork + capability-controlled child)                                │    │
│  │                                                                      │    │
│  │  ┌────────────────────────────────────────────────────────────────┐ │    │
│  │  │                    FORKED CHILD PROCESS                        │ │    │
│  │  │                                                                │ │    │
│  │  │  1. Verify inherited capabilities match expected               │ │    │
│  │  │  2. Apply action-specific seccomp filter                       │ │    │
│  │  │  3. Execute ONLY the validated action struct                   │ │    │
│  │  │  4. Send result via pipe (not serialized user input)           │ │    │
│  │  │  5. _exit() immediately                                        │ │    │
│  │  └────────────────────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Privilege Boundaries

### Boundary 1: Startup → Runtime

**Crosses when:** Privilege drop completes
**Direction:** High → Low privilege
**What crosses:** Pre-opened file descriptors, retained capabilities

| Resource Type | Privileged Phase Action | Runtime Access |
|--------------|-------------------------|----------------|
| Config files | Open `/etc/whitequbit/*` | Read-only FD |
| WAL directory | Open with O_CREAT | Read-write FD |
| Audit log | Open/create file | Append-only FD |
| Unix socket | Bind to privileged path | Accept connections |
| Netlink socket | Open NETLINK_NETFILTER | Send/recv on FD |

### Boundary 2: Main Process → Action Child

**Crosses when:** `fork()` for action execution
**Direction:** Parent → Child → Parent (result)
**What crosses:** Validated action struct, execution result

| Data | Direction | Validation |
|------|-----------|------------|
| Action struct | Parent → Child | Pre-validated, policy-checked |
| Result struct | Child → Parent | Typed enum, no arbitrary strings |
| Exit code | Child → Parent | Numeric only |

## Capabilities Model

### Retained Capabilities (After Privilege Drop)

```rust
pub struct RequiredCapabilities {
    /// CAP_NET_ADMIN - Firewall rule management (iptables/nftables)
    pub net_admin: bool,
    
    /// CAP_KILL - Send signals to any process (service control)
    pub kill: bool,
    
    /// CAP_SYS_PTRACE - Process inspection (optional, off by default)
    pub sys_ptrace: bool,
    
    /// CAP_DAC_READ_SEARCH - Read any file (optional, for scanning)
    pub dac_read_search: bool,
}
```

### Capability Distribution by Action Type

| Action Type | Required Capabilities | Rationale |
|-------------|----------------------|-----------|
| `FirewallAction::Add` | `CAP_NET_ADMIN` | Modify netfilter rules |
| `FirewallAction::Remove` | `CAP_NET_ADMIN` | Modify netfilter rules |
| `ServiceAction::Stop` | `CAP_KILL` | Send SIGTERM to service |
| `ServiceAction::Restart` | `CAP_KILL` | Signal service manager |
| `FileAction::Quarantine` | None (uses pre-opened paths) | Move file to quarantine |
| `ProcessAction::Kill` | `CAP_KILL` | Terminate malicious process |

## IPC Strategy

### Action Execution IPC

The agent uses **pipe-based IPC** for action execution, avoiding the complexity and attack surface of shared memory or network sockets.

```rust
/// Action execution flow with IPC
pub async fn execute_privileged(&self, action: &ValidatedAction) -> Result<ActionResult> {
    // 1. Create pipe for result communication
    let (read_fd, write_fd) = pipe()?;
    
    // 2. Fork child process
    match unsafe { fork() }? {
        ForkResult::Child => {
            // Close read end in child
            close(read_fd)?;
            
            // Apply child-specific restrictions
            self.apply_child_sandbox(action)?;
            
            // Execute action (no shell, no user strings)
            let result = action.execute_direct()?;
            
            // Serialize result as typed struct
            let bytes = bincode::serialize(&result)?;
            write_all(write_fd, &bytes)?;
            
            // Clean exit
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            // Close write end in parent
            close(write_fd)?;
            
            // Read result with timeout
            let result = self.read_result_with_timeout(read_fd, child).await?;
            
            // Reap child
            waitpid(child, None)?;
            
            Ok(result)
        }
    }
}
```

### Command Execution (No Shell!)

**Critical Design Decision:** The agent NEVER uses shell execution.

```rust
/// WRONG - Subject to command injection
fn bad_execute(ip: &str) {
    Command::new("sh")
        .args(["-c", &format!("iptables -A INPUT -s {} -j DROP", ip)])
        .spawn();  // VULNERABLE: ip could contain "; rm -rf /"
}

/// CORRECT - Direct execution with typed arguments
fn good_execute(rule: &FirewallRule) {
    // Validate IP is actually an IP
    let source: IpAddr = rule.source.parse()?;
    
    Command::new("/usr/sbin/iptables")
        .args([
            "-A", "INPUT",
            "-s", &source.to_string(),  // Validated IP only
            "-j", "DROP",
        ])
        .spawn();  // Safe: no shell interpretation
}
```

## Command Injection Prevention

### Input Validation Layers

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: IPC Deserialization                                    │
│ - Strongly typed Action enum                                    │
│ - No arbitrary strings from wire                                │
│ - Schema validation                                             │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: Action Validation                                       │
│ - action.validate() checks semantic correctness                  │
│ - IP addresses parsed as IpAddr                                 │
│ - Ports validated as u16                                        │
│ - Service names checked against allowlist                       │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Policy Check                                           │
│ - PolicyEngine.check_action(&action, &client)                   │
│ - Verifies client is authorized for this action type            │
│ - Rate limiting                                                 │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: Execution Allowlist                                    │
│ - Only predefined executables can be invoked                    │
│ - Paths hardcoded, not from user input                          │
│ - Arguments built from validated typed data                     │
└─────────────────────────────────────────────────────────────────┘
```

### Safe Command Building

```rust
/// Executable allowlist - only these can be invoked
const ALLOWED_EXECUTABLES: &[&str] = &[
    "/usr/sbin/iptables",
    "/usr/sbin/ip6tables", 
    "/usr/sbin/nft",
    "/usr/bin/systemctl",
    "/usr/bin/pkill",
];

/// Build command from validated action (no user strings)
impl FirewallRule {
    pub fn to_command(&self) -> Result<Command, ActionError> {
        let mut cmd = Command::new("/usr/sbin/iptables");
        
        // Chain selection from enum (not string)
        cmd.arg("-A").arg(self.direction.to_string());
        
        // Source IP - already validated as IpAddr
        if let Some(ref source) = self.source {
            let ip: IpAddr = source.parse()
                .map_err(|_| ActionError::Validation("Invalid IP".into()))?;
            cmd.args(["-s", &ip.to_string()]);
        }
        
        // Protocol from enum
        if !matches!(self.protocol, Protocol::All) {
            cmd.args(["-p", &self.protocol.to_string()]);
        }
        
        // Port - already validated as u16
        if let Some(port) = self.port {
            cmd.args(["--dport", &port.to_string()]);
        }
        
        // Target from enum
        cmd.args(["-j", &self.target.to_string()]);
        
        Ok(cmd)
    }
}
```

## Failure Behavior

### Insufficient Privilege Handling

```rust
#[derive(Debug, Clone)]
pub enum PrivilegeFailurePolicy {
    /// Fail the action, log error
    Fail,
    /// Skip the action, continue processing
    Skip,
    /// Queue for retry when capability is available
    Defer,
    /// Request privilege escalation from supervisor
    Escalate,
}

impl ActionExecutor {
    pub async fn execute(&self, action: &dyn Action) -> Result<ActionResult> {
        // Check if we have required capabilities
        let required_caps = action.required_capabilities();
        let available_caps = self.get_current_capabilities()?;
        
        if !required_caps.is_subset(&available_caps) {
            let missing = required_caps.difference(&available_caps);
            
            match self.failure_policy {
                PrivilegeFailurePolicy::Fail => {
                    return Err(ActionError::InsufficientPrivilege {
                        required: required_caps.clone(),
                        missing: missing.collect(),
                    });
                }
                PrivilegeFailurePolicy::Skip => {
                    warn!("Skipping action due to missing capabilities: {:?}", missing);
                    return Ok(ActionResult::skipped("Insufficient privileges"));
                }
                PrivilegeFailurePolicy::Defer => {
                    self.queue_for_retry(action).await?;
                    return Ok(ActionResult::deferred("Queued for privilege escalation"));
                }
                PrivilegeFailurePolicy::Escalate => {
                    return self.request_escalation(action, missing).await;
                }
            }
        }
        
        // Execute with verified capabilities
        self.execute_inner(action).await
    }
}
```

### Capability Verification Before Action

```rust
impl Action for FirewallAction {
    fn required_capabilities(&self) -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        
        match self.operation {
            FirewallOperation::Add | FirewallOperation::Remove |
            FirewallOperation::Insert | FirewallOperation::Flush => {
                caps.insert(Capability::CAP_NET_ADMIN);
            }
        }
        
        caps
    }
    
    fn execute(&self, ctx: &ExecutionContext) -> Result<ActionResult> {
        // Double-check capability at execution time
        if !caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN)? {
            return Err(ActionError::InsufficientPrivilege {
                required: "CAP_NET_ADMIN".into(),
                available: self.get_effective_caps()?,
            });
        }
        
        // Proceed with execution
        self.apply_rule()
    }
}
```

## Security Risks and Mitigations

### Risk 1: Privilege Escalation via Retained Capabilities

**Risk:** An attacker who compromises the agent could abuse retained capabilities.

**Mitigations:**
1. **Minimal capability set:** Only retain capabilities absolutely necessary
2. **Capability bounding set dropped:** Can't regain dropped capabilities
3. **`PR_SET_NO_NEW_PRIVS`:** Prevents setuid binaries from escalating
4. **Seccomp filter:** Blocks syscalls that could abuse capabilities

### Risk 2: Command Injection via Action Parameters

**Risk:** Malicious input in action parameters could execute arbitrary commands.

**Mitigations:**
1. **No shell execution:** Commands built with `Command::new()`, not `sh -c`
2. **Typed arguments:** IPs parsed as `IpAddr`, ports as `u16`, etc.
3. **Enum-based options:** Direction, protocol, target are enums, not strings
4. **Allowlisted executables:** Only specific binaries can be invoked

### Risk 3: IPC Data Tampering

**Risk:** Attacker could inject malicious data via IPC channel.

**Mitigations:**
1. **Unix socket with credentials:** `SO_PEERCRED` verifies client UID/GID
2. **Typed deserialization:** Actions are strongly-typed structs
3. **Schema validation:** Unknown fields rejected
4. **Pipe-based child IPC:** Only internal process communication

### Risk 4: Child Process Escape

**Risk:** Malicious action code could escape sandbox.

**Mitigations:**
1. **Per-action seccomp:** More restrictive than parent process
2. **No execve after fork:** Child can't launch new processes
3. **Landlock filesystem:** Can only access required paths
4. **Timeout + SIGKILL:** Parent forcibly terminates hung children

### Risk 5: Race Conditions in Privilege Drop

**Risk:** TOCTOU between privilege check and privilege use.

**Mitigations:**
1. **Drop order:** GID before UID (can't regain UID without GID)
2. **Atomic capability set:** All caps configured before drop
3. **Supplementary groups cleared:** No unexpected group memberships
4. **Verification after drop:** Confirm privileges actually dropped

### Risk 6: WAL Tampering

**Risk:** Attacker modifies WAL to replay or skip actions.

**Mitigations:**
1. **Append-only file:** Opened with `O_APPEND`
2. **HMAC integrity:** Each entry has cryptographic signature
3. **Monotonic sequence numbers:** Gaps detected
4. **Landed ownership:** WAL file owned by restricted user

## Implementation Checklist

### Phase 1: Core Privilege Separation
- [x] `PrivilegeManager::drop_privileges()` - setuid/setgid
- [x] `PrivilegeManager::setup_capabilities()` - retain needed caps
- [x] `PrivilegeManager::set_no_new_privs()` - prevent escalation
- [ ] Verification after privilege drop
- [ ] Capability verification before action execution

### Phase 2: Command Execution Safety
- [x] No shell execution (`Command::new()` only)
- [x] Typed action parameters (`IpAddr`, `u16`, enums)
- [ ] Executable allowlist enforcement
- [ ] Argument sanitization layer

### Phase 3: IPC Security
- [ ] Unix socket credential verification
- [x] Pipe-based child communication
- [ ] Typed message protocol (bincode/serde)
- [ ] Rate limiting on IPC channel

### Phase 4: Sandbox Hardening
- [x] Seccomp syscall filter
- [x] Landlock filesystem restrictions
- [ ] Per-action seccomp profiles
- [ ] Network namespace isolation

### Phase 5: Failure Handling
- [ ] Capability check before execution
- [ ] Graceful degradation policy
- [ ] Privilege escalation request to supervisor
- [ ] Audit logging of privilege failures

## Testing Privilege Separation

### Test: Privilege Drop Verification
```bash
# Start as root, verify drop
sudo ./target/release/whitequbit-agent &
PID=$!
sleep 1
# Should NOT be root
cat /proc/$PID/status | grep -E "Uid|Gid|CapEff"
# Expected: Uid: 1000 1000 1000 1000 (not 0)
```

### Test: Capability Verification
```bash
# Check effective capabilities
cat /proc/$PID/status | grep CapEff
# Decode with: capsh --decode=<hex>
# Should only show CAP_NET_ADMIN, CAP_KILL
```

### Test: Command Injection Attempt
```bash
# Send malicious action via IPC
echo '{"type":"firewall","source":"8.8.8.8; rm -rf /"}' | \
  socat - UNIX-CONNECT:/var/run/whitequbit/agent.sock

# Should fail validation (not a valid IP)
# Check logs for "Invalid IP address" error
```

### Test: Seccomp Enforcement
```bash
# Attempt disallowed syscall
strace -f -p $PID 2>&1 | grep EPERM
# Should see blocked syscalls returning EPERM
```
