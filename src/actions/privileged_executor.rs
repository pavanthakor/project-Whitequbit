//! Privileged Executor - Secure execution of privileged actions
//!
//! This module implements the privilege-separated action execution model:
//! - Actions are executed in forked child processes
//! - Each child has minimal capabilities for its specific action
//! - No shell execution - commands built from typed parameters
//! - IPC via pipes with typed serialization

use std::collections::HashSet;
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};
use std::time::Duration;

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::io::AsyncReadExt;
#[cfg(unix)]
use tokio::time::timeout;
use tracing::{info, instrument, warn};

use super::action::{Action, ActionResult, ExecutionContext, ValidationError};
use super::ActionError;

/// Execution timeout for privileged actions
#[allow(dead_code)]
const PRIVILEGED_EXEC_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum result size from child process (prevent DoS)
#[allow(dead_code)]
const MAX_RESULT_SIZE: usize = 64 * 1024; // 64KB

/// Allowlisted executables that actions can invoke
pub const ALLOWED_EXECUTABLES: &[&str] = &[
    "/usr/sbin/iptables",
    "/usr/sbin/ip6tables",
    "/usr/sbin/nft",
    "/usr/bin/systemctl",
    "/usr/bin/pkill",
    "/usr/bin/kill",
    "/bin/mv",
    "/bin/chmod",
];

/// Linux capabilities that can be requested
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// CAP_NET_ADMIN - Network configuration, firewall rules
    NetAdmin,
    /// CAP_KILL - Send signals to any process
    Kill,
    /// CAP_SYS_PTRACE - Process inspection
    SysPtrace,
    /// CAP_DAC_READ_SEARCH - Read any file
    DacReadSearch,
    /// CAP_DAC_OVERRIDE - Write any file
    DacOverride,
    /// CAP_CHOWN - Change file ownership
    Chown,
}

impl Capability {
    /// Convert to Linux capability constant
    #[cfg(target_os = "linux")]
    pub fn to_caps_capability(&self) -> caps::Capability {
        match self {
            Capability::NetAdmin => caps::Capability::CAP_NET_ADMIN,
            Capability::Kill => caps::Capability::CAP_KILL,
            Capability::SysPtrace => caps::Capability::CAP_SYS_PTRACE,
            Capability::DacReadSearch => caps::Capability::CAP_DAC_READ_SEARCH,
            Capability::DacOverride => caps::Capability::CAP_DAC_OVERRIDE,
            Capability::Chown => caps::Capability::CAP_CHOWN,
        }
    }
}

/// Set of required capabilities for an action
#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    caps: HashSet<Capability>,
}

impl CapabilitySet {
    /// Create an empty capability set
    pub fn new() -> Self {
        Self {
            caps: HashSet::new(),
        }
    }

    /// Add a capability to the set
    pub fn insert(&mut self, cap: Capability) {
        self.caps.insert(cap);
    }

    /// Check if this set contains a capability
    pub fn contains(&self, cap: &Capability) -> bool {
        self.caps.contains(cap)
    }

    /// Check if this set is a subset of another
    pub fn is_subset(&self, other: &CapabilitySet) -> bool {
        self.caps.is_subset(&other.caps)
    }

    /// Get capabilities in this set but not in other
    pub fn difference<'a>(&'a self, other: &'a CapabilitySet) -> impl Iterator<Item = &'a Capability> {
        self.caps.difference(&other.caps)
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }

    /// Iterate over capabilities
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.caps.iter()
    }
}

/// Policy for handling insufficient privileges
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeFailurePolicy {
    /// Fail the action with an error
    Fail,
    /// Skip the action silently
    Skip,
    /// Queue action for retry when privileges available
    Defer,
}

/// Result from a privileged child process
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
enum ChildResult {
    /// Action succeeded
    Success(ActionResult),
    /// Action failed with error message
    Error(String),
    /// Child was killed or crashed
    Crashed,
}

/// Executor for privileged actions in isolated child processes
pub struct PrivilegedExecutor {
    /// Default execution context
    context: ExecutionContext,
    /// Available capabilities
    available_caps: CapabilitySet,
    /// Policy for insufficient privileges
    failure_policy: PrivilegeFailurePolicy,
}

impl PrivilegedExecutor {
    /// Create a new privileged executor
    pub fn new() -> Self {
        Self {
            context: ExecutionContext::default(),
            available_caps: Self::detect_capabilities(),
            failure_policy: PrivilegeFailurePolicy::Fail,
        }
    }

    /// Create with specific failure policy
    pub fn with_policy(mut self, policy: PrivilegeFailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Detect currently available capabilities
    #[cfg(target_os = "linux")]
    fn detect_capabilities() -> CapabilitySet {
        use caps::{CapSet, Capability as LinuxCap};

        let mut set = CapabilitySet::new();

        let check = |cap: LinuxCap, our_cap: Capability, set: &mut CapabilitySet| {
            if caps::has_cap(None, CapSet::Effective, cap).unwrap_or(false) {
                set.insert(our_cap);
            }
        };

        check(LinuxCap::CAP_NET_ADMIN, Capability::NetAdmin, &mut set);
        check(LinuxCap::CAP_KILL, Capability::Kill, &mut set);
        check(LinuxCap::CAP_SYS_PTRACE, Capability::SysPtrace, &mut set);
        check(LinuxCap::CAP_DAC_READ_SEARCH, Capability::DacReadSearch, &mut set);
        check(LinuxCap::CAP_DAC_OVERRIDE, Capability::DacOverride, &mut set);
        check(LinuxCap::CAP_CHOWN, Capability::Chown, &mut set);

        set
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_capabilities() -> CapabilitySet {
        // On non-Linux, assume all capabilities (for testing)
        let mut set = CapabilitySet::new();
        set.insert(Capability::NetAdmin);
        set.insert(Capability::Kill);
        set
    }

    /// Execute an action with privilege verification
    #[instrument(skip(self, action), fields(action_type = action.action_type()))]
    pub async fn execute(&self, action: &dyn Action) -> Result<ActionResult, ActionError> {
        let required = action.required_capabilities();

        // Check if we have required capabilities
        if !required.is_subset(&self.available_caps) {
            let missing: Vec<_> = required.difference(&self.available_caps).collect();
            warn!(?missing, "Insufficient capabilities for action");

            return match self.failure_policy {
                PrivilegeFailurePolicy::Fail => Err(ActionError::InsufficientPrivilege(format!(
                    "Missing capabilities: {:?}",
                    missing
                ))),
                PrivilegeFailurePolicy::Skip => {
                    info!("Skipping action due to missing capabilities");
                    Ok(ActionResult::skipped("Insufficient privileges"))
                }
                PrivilegeFailurePolicy::Defer => {
                    info!("Deferring action for later retry");
                    Ok(ActionResult::deferred("Awaiting privilege escalation"))
                }
            };
        }

        // Execute in forked child for isolation
        #[cfg(unix)]
        {
            self.execute_forked(action).await
        }

        #[cfg(not(unix))]
        {
            self.execute_direct(action).await
        }
    }

    /// Execute directly (non-Unix fallback)
    #[cfg(not(unix))]
    async fn execute_direct(&self, action: &dyn Action) -> Result<ActionResult, ActionError> {
        action.execute(&self.context)
    }

    /// Execute action in a forked child process
    #[cfg(unix)]
    async fn execute_forked(&self, action: &dyn Action) -> Result<ActionResult, ActionError> {
        use nix::sys::wait::{waitpid, WaitStatus};
        use nix::unistd::{close, fork, pipe, ForkResult};
        use std::io::{Read, Write};

        // Create pipe for IPC
        let (read_fd, write_fd) = pipe()
            .map_err(|e| ActionError::Sandbox(format!("Failed to create pipe: {}", e)))?;

        debug!("Forking child for privileged action");

        // Fork child process
        // SAFETY: fork() is safe here because we immediately handle both parent and
        // child cases. The child process doesn't use any async runtime resources;
        // it synchronously executes the action and exits.
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                // === CHILD PROCESS ===
                
                // Close read end (we only write)
                let _ = close(read_fd);

                // Apply additional sandbox restrictions
                if let Err(e) = self.apply_child_sandbox(action) {
                    let error = ChildResult::Error(format!("Sandbox failed: {}", e));
                    let _ = Self::write_result(write_fd, &error);
                    std::process::exit(1);
                }

                // Verify we have the required capabilities
                let required = action.required_capabilities();
                if let Err(e) = Self::verify_capabilities(&required) {
                    let error = ChildResult::Error(format!("Capability check failed: {}", e));
                    let _ = Self::write_result(write_fd, &error);
                    std::process::exit(1);
                }

                // Execute the action
                let result = match action.execute(&self.context) {
                    Ok(r) => ChildResult::Success(r),
                    Err(e) => ChildResult::Error(e.to_string()),
                };

                // Write result and exit
                let _ = Self::write_result(write_fd, &result);
                std::process::exit(0);
            }
            Ok(ForkResult::Parent { child }) => {
                // === PARENT PROCESS ===
                
                // Close write end (we only read)
                let _ = close(write_fd);

                // Read result with timeout
                let result = timeout(
                    PRIVILEGED_EXEC_TIMEOUT,
                    Self::read_result(read_fd),
                )
                .await;

                // Close read end
                let _ = close(read_fd);

                // Handle timeout
                let child_result = match result {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        // Kill the child if it's still running
                        let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                        let _ = waitpid(child, None);
                        return Err(ActionError::Sandbox(format!("Failed to read result: {}", e)));
                    }
                    Err(_) => {
                        // Timeout - kill the child
                        error!("Action timed out, killing child process");
                        let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                        let _ = waitpid(child, None);
                        return Err(ActionError::Timeout(PRIVILEGED_EXEC_TIMEOUT));
                    }
                };

                // Wait for child to exit
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, 0)) => {
                        // Normal exit - use the result
                    }
                    Ok(WaitStatus::Exited(_, code)) => {
                        warn!(exit_code = code, "Child exited with error");
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        error!(?sig, "Child killed by signal");
                        return Err(ActionError::Execution(format!("Child killed by {:?}", sig)));
                    }
                    _ => {}
                }

                // Parse the child result
                match child_result {
                    ChildResult::Success(r) => Ok(r),
                    ChildResult::Error(e) => Err(ActionError::Execution(e)),
                    ChildResult::Crashed => Err(ActionError::Execution("Child crashed".into())),
                }
            }
            Err(e) => Err(ActionError::Sandbox(format!("Fork failed: {}", e))),
        }
    }

    /// Write result to pipe in child process
    #[cfg(unix)]
    fn write_result(fd: RawFd, result: &ChildResult) -> Result<(), ActionError> {
        use std::io::Write;

        let bytes = bincode::serialize(result)
            .map_err(|e| ActionError::Serialization(format!("Failed to serialize result: {}", e)))?;

        // Write length prefix
        let len = bytes.len() as u32;
        let len_bytes = len.to_le_bytes();

        // SAFETY: fd is a valid file descriptor from pipe() created in execute_forked,
        // passed to child after fork. We own this fd in the child process.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(&len_bytes)
            .map_err(|e| ActionError::Sandbox(format!("Failed to write length: {}", e)))?;
        file.write_all(&bytes)
            .map_err(|e| ActionError::Sandbox(format!("Failed to write result: {}", e)))?;

        // Don't close the fd - we'll exit anyway
        std::mem::forget(file);
        Ok(())
    }

    /// Read result from pipe in parent process
    #[cfg(unix)]
    async fn read_result(fd: RawFd) -> Result<ChildResult, ActionError> {
        use std::os::unix::io::AsRawFd;
        use tokio::io::AsyncReadExt;

        // Convert to async file
        // SAFETY: fd is a valid file descriptor from pipe() created in execute_forked
        let std_file = unsafe { std::fs::File::from_raw_fd(fd) };
        
        // Set non-blocking mode using fcntl (std::fs::File doesn't have set_nonblocking)
        {
            let raw_fd = std_file.as_raw_fd();
            // SAFETY: fcntl with F_GETFL/F_SETFL is safe for valid file descriptors
            let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(ActionError::Sandbox(format!(
                    "Failed to get fd flags: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let result = unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if result < 0 {
                return Err(ActionError::Sandbox(format!(
                    "Failed to set nonblocking: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        
        let mut file = tokio::fs::File::from_std(std_file);

        // Read length prefix
        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes).await.map_err(|e| {
            ActionError::Sandbox(format!("Failed to read length: {}", e))
        })?;

        let len = u32::from_le_bytes(len_bytes) as usize;

        // Validate length
        if len > MAX_RESULT_SIZE {
            return Err(ActionError::Sandbox(format!(
                "Result too large: {} bytes (max {})",
                len, MAX_RESULT_SIZE
            )));
        }

        // Read result
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes).await.map_err(|e| {
            ActionError::Sandbox(format!("Failed to read result: {}", e))
        })?;

        // Deserialize
        bincode::deserialize(&bytes)
            .map_err(|e| ActionError::Serialization(format!("Failed to deserialize result: {}", e)))
    }

    /// Apply additional sandbox restrictions in child process
    #[allow(dead_code)]
    fn apply_child_sandbox(&self, _action: &dyn Action) -> Result<(), ActionError> {
        // In production, apply action-specific seccomp filter
        // For now, we rely on the parent's sandbox
        
        #[cfg(target_os = "linux")]
        {
            // Verify no_new_privs is set
            use libc::{prctl, PR_GET_NO_NEW_PRIVS};
            // SAFETY: prctl with PR_GET_NO_NEW_PRIVS is a read-only query that is always safe
            let result = unsafe { prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
            if result != 1 {
                // Set it if not already set
                use libc::PR_SET_NO_NEW_PRIVS;
                // SAFETY: prctl with PR_SET_NO_NEW_PRIVS prevents privilege escalation
                // and is always safe to call
                let result = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
                if result != 0 {
                    return Err(ActionError::Sandbox("Failed to set NO_NEW_PRIVS".into()));
                }
            }
        }

        Ok(())
    }

    /// Verify required capabilities are available
    #[cfg(target_os = "linux")]
    fn verify_capabilities(required: &CapabilitySet) -> Result<(), ActionError> {
        use caps::CapSet;

        for cap in required.iter() {
            let linux_cap = cap.to_caps_capability();
            if !caps::has_cap(None, CapSet::Effective, linux_cap)
                .map_err(|e| ActionError::Sandbox(format!("Failed to check capability: {}", e)))?
            {
                return Err(ActionError::InsufficientPrivilege(format!(
                    "Missing capability: {:?}",
                    cap
                )));
            }
        }

        Ok(())
    }

    /// Verify capabilities (non-Linux fallback)
    #[allow(dead_code)]
    #[cfg(not(target_os = "linux"))]
    fn verify_capabilities(_required: &CapabilitySet) -> Result<(), ActionError> {
        Ok(())
    }
}

impl Default for PrivilegedExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait extension for actions that require capabilities
pub trait PrivilegedAction: Action {
    /// Get the capabilities required by this action
    fn required_capabilities(&self) -> CapabilitySet;
}

/// Validate that a path is in the allowlist of executables
pub fn validate_executable(path: &str) -> Result<(), ValidationError> {
    if !ALLOWED_EXECUTABLES.contains(&path) {
        return Err(ValidationError::InvalidValue {
            field: "executable".to_string(),
            reason: format!("Executable not in allowlist: {}", path),
        });
    }
    Ok(())
}

/// Sanitize a string for use in command arguments (no shell interpretation)
pub fn sanitize_argument(arg: &str) -> Result<String, ValidationError> {
    // Reject any shell metacharacters
    const FORBIDDEN_CHARS: &[char] = &[
        ';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']',
        '<', '>', '\'', '"', '\\', '\n', '\r', '\0',
    ];

    for c in FORBIDDEN_CHARS {
        if arg.contains(*c) {
            return Err(ValidationError::InvalidValue {
                field: "argument".to_string(),
                reason: format!("Argument contains forbidden character: {:?}", c),
            });
        }
    }

    Ok(arg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_set() {
        let mut set1 = CapabilitySet::new();
        set1.insert(Capability::NetAdmin);
        set1.insert(Capability::Kill);

        let mut set2 = CapabilitySet::new();
        set2.insert(Capability::NetAdmin);

        assert!(set2.is_subset(&set1));
        assert!(!set1.is_subset(&set2));
    }

    #[test]
    fn test_validate_executable() {
        assert!(validate_executable("/usr/sbin/iptables").is_ok());
        assert!(validate_executable("/bin/sh").is_err());
        assert!(validate_executable("iptables").is_err()); // Must be absolute path
    }

    #[test]
    fn test_sanitize_argument() {
        assert!(sanitize_argument("192.168.1.1").is_ok());
        assert!(sanitize_argument("DROP").is_ok());
        assert!(sanitize_argument("8080").is_ok());
        
        // Shell metacharacters rejected
        assert!(sanitize_argument("8.8.8.8; rm -rf /").is_err());
        assert!(sanitize_argument("$(whoami)").is_err());
        assert!(sanitize_argument("foo`id`bar").is_err());
        assert!(sanitize_argument("a|b").is_err());
        assert!(sanitize_argument("a&b").is_err());
    }
}
