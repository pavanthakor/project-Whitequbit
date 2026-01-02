//! Sandbox Manager - Process sandboxing with seccomp/landlock
//!
//! Applies syscall filtering and filesystem restrictions.

use std::path::PathBuf;

use tracing::{debug, info, warn};

use crate::config::SecurityConfig;

use super::SecurityError;

/// Sandbox configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxConfig {
    /// Enable seccomp filtering
    pub enable_seccomp: bool,
    /// Enable landlock filesystem restrictions
    pub enable_landlock: bool,
    /// Allowed read-only paths
    pub readonly_paths: Vec<PathBuf>,
    /// Allowed read-write paths
    pub readwrite_paths: Vec<PathBuf>,
    /// Allowed execute paths (for spawning)
    pub execute_paths: Vec<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enable_seccomp: true,
            enable_landlock: true,
            readonly_paths: vec![
                PathBuf::from("/etc/whitequbit"),
                PathBuf::from("/usr"),
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
            ],
            readwrite_paths: vec![
                PathBuf::from("/var/lib/whitequbit"),
                PathBuf::from("/var/log/whitequbit"),
                PathBuf::from("/var/run/whitequbit"),
            ],
            execute_paths: vec![],
        }
    }
}

/// Manager for sandbox application
pub struct SandboxManager {
    config: SandboxConfig,
}

impl SandboxManager {
    /// Create a new sandbox manager from security config
    pub fn new(config: &SecurityConfig) -> Result<Self, SecurityError> {
        Ok(Self {
            config: config.sandbox.clone(),
        })
    }

    /// Create with specific sandbox config
    pub fn with_config(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Apply all sandbox restrictions
    pub fn apply_sandbox(&self) -> Result<(), SecurityError> {
        info!("Applying sandbox restrictions");

        // Apply landlock first (filesystem restrictions)
        if self.config.enable_landlock {
            self.apply_landlock()?;
        }

        // Apply seccomp (syscall filtering)
        if self.config.enable_seccomp {
            self.apply_seccomp()?;
        }

        info!("Sandbox applied successfully");
        Ok(())
    }

    /// Apply landlock filesystem restrictions
    #[cfg(target_os = "linux")]
    fn apply_landlock(&self) -> Result<(), SecurityError> {
        use landlock::{
            Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            ABI,
        };

        // Check if landlock is supported
        let abi = ABI::V1;

        let ruleset = Ruleset::new()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| SecurityError::Sandbox(format!("Failed to create ruleset: {}", e)))?;

        // Create the ruleset
        let mut ruleset = ruleset
            .create()
            .map_err(|e| SecurityError::Sandbox(format!("Failed to create ruleset: {}", e)))?;

        // Add read-only paths
        for path in &self.config.readonly_paths {
            if path.exists() {
                let fd = PathFd::new(path)
                    .map_err(|e| SecurityError::Sandbox(format!("Failed to open path {}: {}", path.display(), e)))?;

                // add_rule returns Result<Self, ...>, so reassign ruleset
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
                    .map_err(|e| SecurityError::Sandbox(format!("Failed to add rule: {}", e)))?;

                debug!("Landlock: added read-only {}", path.display());
            }
        }

        // Add read-write paths
        for path in &self.config.readwrite_paths {
            if path.exists() {
                let fd = PathFd::new(path)
                    .map_err(|e| SecurityError::Sandbox(format!("Failed to open path {}: {}", path.display(), e)))?;

                // add_rule returns Result<Self, ...>, so reassign ruleset
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))
                    .map_err(|e| SecurityError::Sandbox(format!("Failed to add rule: {}", e)))?;

                debug!("Landlock: added read-write {}", path.display());
            }
        }

        // Enforce the ruleset
        ruleset
            .restrict_self()
            .map_err(|e| SecurityError::Sandbox(format!("Failed to restrict self: {}", e)))?;

        info!("Landlock sandbox applied");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn apply_landlock(&self) -> Result<(), SecurityError> {
        warn!("Landlock not supported on this platform");
        Ok(())
    }

    /// Apply seccomp syscall filtering
    #[cfg(target_os = "linux")]
    fn apply_seccomp(&self) -> Result<(), SecurityError> {
        use seccompiler::{
            SeccompAction, SeccompFilter, SeccompRule,
        };
        use std::collections::BTreeMap;

        // Build allowlist of syscalls
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // Basic I/O
        let allowed_syscalls = [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_close,
            libc::SYS_fstat,
            libc::SYS_lseek,
            libc::SYS_pread64,
            libc::SYS_pwrite64,

            // Memory management
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_brk,

            // Async I/O
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_eventfd2,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,

            // Sockets (Unix only)
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_shutdown,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,

            // File operations
            libc::SYS_openat,
            libc::SYS_newfstatat,
            libc::SYS_access,
            libc::SYS_faccessat,
            libc::SYS_dup,
            libc::SYS_dup2,
            libc::SYS_dup3,
            libc::SYS_fcntl,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_ftruncate,
            libc::SYS_getdents64,
            libc::SYS_lstat,
            libc::SYS_stat,
            libc::SYS_readlink,
            libc::SYS_readlinkat,
            libc::SYS_unlink,
            libc::SYS_unlinkat,
            libc::SYS_rename,
            libc::SYS_renameat,
            libc::SYS_mkdir,
            libc::SYS_mkdirat,

            // Process
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_execve,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_wait4,
            libc::SYS_waitid,
            libc::SYS_kill,

            // Signals
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack,

            // Time
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_gettimeofday,
            libc::SYS_nanosleep,
            libc::SYS_clock_nanosleep,

            // Info
            libc::SYS_getpid,
            libc::SYS_getppid,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_uname,

            // Misc
            libc::SYS_getrandom,
            libc::SYS_pipe2,
            libc::SYS_ioctl,
            libc::SYS_prctl,
            libc::SYS_futex,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_yield,
        ];

        for syscall in allowed_syscalls {
            rules.insert(syscall, vec![SeccompRule::new(vec![]).unwrap()]);
        }

        // Create the filter
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32), // Default: deny with EPERM
            SeccompAction::Allow, // Matches: allow
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .map_err(|e| SecurityError::Sandbox(format!("Failed to create seccomp filter: {}", e)))?;

        // Compile the filter to BPF bytecode
        // SeccompFilter::try_into() returns a Vec<sock_filter> (BPF program), not a HashMap
        let bpf_prog: seccompiler::BpfProgram = filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| SecurityError::Sandbox(format!("Failed to compile filter: {:?}", e)))?;

        // Apply the compiled BPF program to this thread
        seccompiler::apply_filter(&bpf_prog)
            .map_err(|e| SecurityError::Sandbox(format!("Failed to apply seccomp: {}", e)))?;

        info!("Seccomp filter applied ({} syscalls allowed)", allowed_syscalls.len());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn apply_seccomp(&self) -> Result<(), SecurityError> {
        warn!("Seccomp not supported on this platform");
        Ok(())
    }

    /// Check if sandbox is currently active
    #[cfg(target_os = "linux")]
    pub fn is_sandboxed() -> bool {
        // Check if seccomp is enabled
        use std::fs;

        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("Seccomp:") {
                    let value = line.split(':').nth(1).unwrap_or("0").trim();
                    return value != "0";
                }
            }
        }

        false
    }

    /// Check if we're running in a sandbox (non-Linux fallback)
    #[cfg(not(target_os = "linux"))]
    pub fn is_sandboxed() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert!(config.enable_seccomp);
        assert!(config.enable_landlock);
        assert!(!config.readonly_paths.is_empty());
    }
}
