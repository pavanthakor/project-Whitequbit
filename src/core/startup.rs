//! Startup Checks - Runtime environment validation
//!
//! Performs critical pre-flight checks before the agent starts:
//! - Runtime directory existence and permissions
//! - Systemd detection and compatibility
//! - Capability validation
//! - Kernel feature detection (Landlock, Seccomp)
//!
//! # Systemd Integration
//!
//! When running under systemd, the following directives are required:
//!
//! ```ini
//! [Service]
//! RuntimeDirectory=whitequbit
//! StateDirectory=whitequbit
//! LogsDirectory=whitequbit
//! ReadWritePaths=/var/lib/whitequbit /var/log/whitequbit /run/whitequbit
//! ```
//!
//! If `ProtectSystem=strict` is enabled, `ReadWritePaths` MUST include
//! all directories the agent writes to.

use std::path::{Path, PathBuf};
use std::fs;

use crate::config::AgentConfig;
use super::CoreError;

/// Required runtime directories
pub const REQUIRED_DIRS: &[&str] = &[
    "/var/lib/whitequbit",
    "/var/log/whitequbit",
    "/run/whitequbit",
];

/// Result of startup checks
#[derive(Debug)]
pub struct StartupCheckResult {
    /// Whether all checks passed
    pub passed: bool,
    /// Detailed check results
    pub checks: Vec<CheckResult>,
    /// Whether running under systemd
    pub is_systemd: bool,
}

/// Individual check result
#[derive(Debug)]
pub struct CheckResult {
    /// Check name
    pub name: String,
    /// Whether the check passed
    pub passed: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Fix suggestion if failed
    pub fix_suggestion: Option<String>,
}

impl CheckResult {
    fn pass(name: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            error: None,
            fix_suggestion: None,
        }
    }

    fn fail(name: &str, error: &str, fix: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            error: Some(error.to_string()),
            fix_suggestion: Some(fix.to_string()),
        }
    }
}

/// Startup checker for pre-flight validation
pub struct StartupChecker {
    config: AgentConfig,
}

impl StartupChecker {
    /// Create a new startup checker
    pub fn new(config: &AgentConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Run all startup checks
    pub fn run_all_checks(&self) -> StartupCheckResult {
        let is_systemd = Self::detect_systemd();
        let mut checks = Vec::new();

        // Directory checks
        checks.extend(self.check_runtime_directories());

        // Path writability checks
        checks.extend(self.check_path_writability());

        // Capability checks (Linux only)
        #[cfg(target_os = "linux")]
        if self.config.security.drop_privileges {
            checks.extend(self.check_capabilities());
        }

        // Kernel feature checks (Linux only)
        #[cfg(target_os = "linux")]
        if self.config.security.apply_sandbox {
            checks.extend(self.check_kernel_features());
        }

        // Firewall backend checks
        #[cfg(target_os = "linux")]
        checks.extend(self.check_firewall_backend());

        // User existence check
        #[cfg(unix)]
        if self.config.security.drop_privileges {
            checks.extend(self.check_target_user());
        }

        let passed = checks.iter().all(|c| c.passed);

        StartupCheckResult {
            passed,
            checks,
            is_systemd,
        }
    }

    /// Check if running under systemd
    pub fn detect_systemd() -> bool {
        // Check for INVOCATION_ID (set by systemd for all services)
        if std::env::var("INVOCATION_ID").is_ok() {
            return true;
        }
        // Check for NOTIFY_SOCKET (Type=notify services)
        if std::env::var("NOTIFY_SOCKET").is_ok() {
            return true;
        }
        // Check if parent is PID 1 (systemd)
        #[cfg(unix)]
        {
            if let Ok(ppid) = std::fs::read_to_string("/proc/self/stat") {
                let parts: Vec<&str> = ppid.split_whitespace().collect();
                if parts.len() > 3 {
                    if let Ok(parent_pid) = parts[3].parse::<u32>() {
                        if parent_pid == 1 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check runtime directories exist and are writable
    fn check_runtime_directories(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        for dir in REQUIRED_DIRS {
            let path = Path::new(dir);
            let name = format!("directory_{}", dir.replace('/', "_"));

            if !path.exists() {
                let fix = if Self::detect_systemd() {
                    format!(
                        "Add to systemd unit file:\n\
                         [Service]\n\
                         RuntimeDirectory=whitequbit\n\
                         StateDirectory=whitequbit\n\
                         LogsDirectory=whitequbit\n\
                         \n\
                         Or manually create:\n\
                         sudo mkdir -p {}\n\
                         sudo chown whitequbit:whitequbit {}",
                        dir, dir
                    )
                } else {
                    format!(
                        "Create the directory:\n\
                         sudo mkdir -p {}\n\
                         sudo chown whitequbit:whitequbit {}",
                        dir, dir
                    )
                };

                results.push(CheckResult::fail(
                    &name,
                    &format!("Required directory does not exist: {}", dir),
                    &fix,
                ));
            } else {
                // Check write access
                let test_file = path.join(".whitequbit_write_test");
                match fs::write(&test_file, "test") {
                    Ok(_) => {
                        let _ = fs::remove_file(&test_file);
                        results.push(CheckResult::pass(&name));
                    }
                    Err(e) => {
                        let fix = if e.kind() == std::io::ErrorKind::ReadOnlyFilesystem
                            || e.raw_os_error() == Some(30)
                        // EROFS
                        {
                            format!(
                                "Filesystem is read-only. If using systemd with ProtectSystem=strict:\n\
                                 [Service]\n\
                                 ReadWritePaths={}\n\
                                 \n\
                                 Or disable ProtectSystem if not needed.",
                                dir
                            )
                        } else {
                            format!(
                                "Fix permissions:\n\
                                 sudo chown -R whitequbit:whitequbit {}\n\
                                 sudo chmod 755 {}",
                                dir, dir
                            )
                        };

                        results.push(CheckResult::fail(
                            &name,
                            &format!("Cannot write to {}: {}", dir, e),
                            &fix,
                        ));
                    }
                }
            }
        }

        results
    }

    /// Check that configured paths are writable
    fn check_path_writability(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        // Check WAL path
        results.push(self.check_path_writable("wal_path", &self.config.wal_path));

        // Check audit path
        results.push(self.check_path_writable("audit_path", &self.config.audit_path));

        // Check socket path parent
        if let Some(parent) = self.config.socket_path.parent() {
            results.push(self.check_path_writable("socket_dir", &parent.to_path_buf()));
        }

        // Check PID path parent
        if let Some(parent) = self.config.pid_path.parent() {
            results.push(self.check_path_writable("pid_dir", &parent.to_path_buf()));
        }

        results
    }

    fn check_path_writable(&self, name: &str, path: &PathBuf) -> CheckResult {
        let check_path = if path.is_dir() {
            path.clone()
        } else {
            path.parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("/"))
        };

        if !check_path.exists() {
            // Parent doesn't exist - might be created later
            return CheckResult::pass(name);
        }

        let test_file = check_path.join(".whitequbit_write_test");
        match fs::write(&test_file, "test") {
            Ok(_) => {
                let _ = fs::remove_file(&test_file);
                CheckResult::pass(name)
            }
            Err(e) => {
                let is_readonly = e.kind() == std::io::ErrorKind::ReadOnlyFilesystem
                    || e.raw_os_error() == Some(30);

                let fix = if is_readonly && Self::detect_systemd() {
                    format!(
                        "Filesystem is read-only (ProtectSystem=strict may be enabled).\n\
                         Add to systemd unit:\n\
                         [Service]\n\
                         ReadWritePaths={}",
                        check_path.display()
                    )
                } else {
                    format!(
                        "Cannot write to {}. Fix permissions:\n\
                         sudo chown whitequbit:whitequbit {}\n\
                         sudo chmod 755 {}",
                        check_path.display(),
                        check_path.display(),
                        check_path.display()
                    )
                };

                CheckResult::fail(
                    name,
                    &format!("Path not writable: {} ({})", path.display(), e),
                    &fix,
                )
            }
        }
    }

    /// Check required capabilities (Linux only)
    #[cfg(target_os = "linux")]
    fn check_capabilities(&self) -> Vec<CheckResult> {
        use caps::{CapSet, Capability, has_cap};

        let mut results = Vec::new();

        // Check CAP_NET_ADMIN
        let has_net_admin = has_cap(None, CapSet::Permitted, Capability::CAP_NET_ADMIN)
            .unwrap_or(false);

        if !has_net_admin {
            results.push(CheckResult::fail(
                "cap_net_admin",
                "CAP_NET_ADMIN capability is required for firewall management",
                "Grant the capability:\n\
                 sudo setcap 'cap_net_admin+ep' /usr/bin/whitequbit-agent\n\
                 \n\
                 Or in systemd:\n\
                 [Service]\n\
                 AmbientCapabilities=CAP_NET_ADMIN",
            ));
        } else {
            results.push(CheckResult::pass("cap_net_admin"));
        }

        // Check CAP_KILL
        let has_kill = has_cap(None, CapSet::Permitted, Capability::CAP_KILL)
            .unwrap_or(false);

        if !has_kill {
            results.push(CheckResult::fail(
                "cap_kill",
                "CAP_KILL capability is required for service management",
                "Grant the capability:\n\
                 sudo setcap 'cap_kill+ep' /usr/bin/whitequbit-agent\n\
                 \n\
                 Or in systemd:\n\
                 [Service]\n\
                 AmbientCapabilities=CAP_KILL",
            ));
        } else {
            results.push(CheckResult::pass("cap_kill"));
        }

        results
    }

    /// Check kernel features (Linux only)
    #[cfg(target_os = "linux")]
    fn check_kernel_features(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        // Check Landlock support
        if self.config.security.sandbox.enable_landlock {
            results.push(self.check_landlock_support());
        }

        // Check seccomp support
        if self.config.security.sandbox.enable_seccomp {
            results.push(self.check_seccomp_support());
        }

        results
    }

    #[cfg(target_os = "linux")]
    fn check_landlock_support(&self) -> CheckResult {
        // Try to detect Landlock ABI version
        let landlock_abi_path = "/sys/kernel/security/landlock/abi";

        if Path::new(landlock_abi_path).exists() {
            if let Ok(version) = fs::read_to_string(landlock_abi_path) {
                let version = version.trim();
                tracing::info!("Landlock ABI version: {}", version);
                return CheckResult::pass("landlock");
            }
        }

        // Alternative: try syscall directly
        // For now, check kernel version (Landlock requires >= 5.13)
        if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = release.split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    if major > 5 || (major == 5 && minor >= 13) {
                        // Kernel version supports Landlock
                        return CheckResult::pass("landlock");
                    }
                }
            }
        }

        CheckResult::fail(
            "landlock",
            "Landlock filesystem sandboxing is not supported on this kernel",
            "Landlock requires Linux kernel 5.13 or later.\n\
             Options:\n\
             1. Upgrade kernel to 5.13+\n\
             2. Disable Landlock in config:\n\
                [security.sandbox]\n\
                enable_landlock = false\n\
             \n\
             WARNING: Disabling Landlock reduces security isolation.",
        )
    }

    #[cfg(target_os = "linux")]
    fn check_seccomp_support(&self) -> CheckResult {
        // Check if seccomp is available via /proc
        let seccomp_path = "/proc/sys/kernel/seccomp/actions_avail";

        if Path::new(seccomp_path).exists() {
            return CheckResult::pass("seccomp");
        }

        // Alternative: check prctl availability
        // seccomp has been in Linux since 2.6.12 (2005), so this is rare
        if Path::new("/proc/self/seccomp").exists() {
            return CheckResult::pass("seccomp");
        }

        CheckResult::fail(
            "seccomp",
            "Seccomp syscall filtering is not available",
            "Seccomp requires Linux kernel 3.5+ with CONFIG_SECCOMP=y.\n\
             This is unusual - most modern kernels have seccomp.\n\
             \n\
             To disable (NOT RECOMMENDED):\n\
             [security.sandbox]\n\
             enable_seccomp = false",
        )
    }

    /// Check firewall backend availability
    #[cfg(target_os = "linux")]
    fn check_firewall_backend(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        // Check iptables binary
        let iptables_paths = ["/sbin/iptables", "/usr/sbin/iptables", "/bin/iptables"];
        let iptables_found = iptables_paths.iter().any(|p| Path::new(p).exists());

        if !iptables_found {
            results.push(CheckResult::fail(
                "iptables",
                "iptables binary not found",
                "Install iptables:\n\
                 Debian/Ubuntu: sudo apt install iptables\n\
                 RHEL/CentOS: sudo yum install iptables\n\
                 Arch: sudo pacman -S iptables",
            ));
        } else {
            results.push(CheckResult::pass("iptables"));
        }

        results
    }

    /// Check target user exists (Unix only)
    #[cfg(unix)]
    fn check_target_user(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        let uid = self.config.security.target_uid;
        let gid = self.config.security.target_gid;

        // Check if user exists by reading /etc/passwd
        let user_exists = if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            passwd.lines().any(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                parts.len() > 2 && parts[2].parse::<u32>().ok() == Some(uid)
            })
        } else {
            // Can't read passwd, assume it might exist
            true
        };

        if !user_exists && uid != 65534 {
            results.push(CheckResult::fail(
                "target_user",
                &format!("Target user (UID {}) does not exist", uid),
                &format!(
                    "Create the service user:\n\
                     sudo useradd -r -s /sbin/nologin -u {} whitequbit\n\
                     \n\
                     Or update config to use an existing user:\n\
                     [security]\n\
                     target_uid = <existing_uid>\n\
                     target_gid = <existing_gid>",
                    uid
                ),
            ));
        } else {
            results.push(CheckResult::pass("target_user"));
        }

        // Check group exists
        let group_exists = if let Ok(group) = fs::read_to_string("/etc/group") {
            group.lines().any(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                parts.len() > 2 && parts[2].parse::<u32>().ok() == Some(gid)
            })
        } else {
            true
        };

        if !group_exists && gid != 65534 {
            results.push(CheckResult::fail(
                "target_group",
                &format!("Target group (GID {}) does not exist", gid),
                &format!(
                    "Create the service group:\n\
                     sudo groupadd -r -g {} whitequbit\n\
                     \n\
                     Or update config to use an existing group.",
                    gid
                ),
            ));
        } else {
            results.push(CheckResult::pass("target_group"));
        }

        results
    }

    /// Format check results for logging
    pub fn format_results(result: &StartupCheckResult) -> String {
        let mut output = String::new();

        output.push_str("=== WhiteQubit Agent Startup Checks ===\n\n");

        if result.is_systemd {
            output.push_str("Running under: systemd\n\n");
        } else {
            output.push_str("Running under: standalone\n\n");
        }

        let passed = result.checks.iter().filter(|c| c.passed).count();
        let total = result.checks.len();
        output.push_str(&format!("Checks: {}/{} passed\n\n", passed, total));

        for check in &result.checks {
            let status = if check.passed { "✓" } else { "✗" };
            output.push_str(&format!("[{}] {}\n", status, check.name));

            if let Some(ref error) = check.error {
                output.push_str(&format!("    Error: {}\n", error));
            }

            if let Some(ref fix) = check.fix_suggestion {
                output.push_str("    Fix:\n");
                for line in fix.lines() {
                    output.push_str(&format!("      {}\n", line));
                }
            }
        }

        if !result.passed {
            output.push_str("\n=== STARTUP FAILED ===\n");
            output.push_str("Fix the above issues and restart the agent.\n");
        }

        output
    }
}

/// Run startup checks and fail fast if critical issues found
pub fn run_startup_checks(config: &AgentConfig) -> Result<(), CoreError> {
    let checker = StartupChecker::new(config);
    let result = checker.run_all_checks();

    // Log all results
    for check in &result.checks {
        if check.passed {
            tracing::debug!(check = %check.name, "Startup check passed");
        } else {
            tracing::error!(
                check = %check.name,
                error = ?check.error,
                fix = ?check.fix_suggestion,
                "Startup check FAILED"
            );
        }
    }

    if !result.passed {
        let formatted = StartupChecker::format_results(&result);
        eprintln!("{}", formatted);

        // Count critical failures
        let failures: Vec<_> = result.checks.iter().filter(|c| !c.passed).collect();
        return Err(CoreError::StartupCheck(format!(
            "{} startup check(s) failed. See above for details.",
            failures.len()
        )));
    }

    tracing::info!(
        checks_passed = result.checks.len(),
        systemd = result.is_systemd,
        "All startup checks passed"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result_pass() {
        let result = CheckResult::pass("test_check");
        assert!(result.passed);
        assert!(result.error.is_none());
        assert!(result.fix_suggestion.is_none());
    }

    #[test]
    fn test_check_result_fail() {
        let result = CheckResult::fail("test_check", "error msg", "fix suggestion");
        assert!(!result.passed);
        assert_eq!(result.error.as_deref(), Some("error msg"));
        assert_eq!(result.fix_suggestion.as_deref(), Some("fix suggestion"));
    }

    #[test]
    fn test_startup_check_result_all_pass() {
        let result = StartupCheckResult {
            passed: true,
            checks: vec![CheckResult::pass("check1"), CheckResult::pass("check2")],
            is_systemd: false,
        };
        assert!(result.passed);
    }

    #[test]
    fn test_format_results() {
        let result = StartupCheckResult {
            passed: false,
            checks: vec![
                CheckResult::pass("good_check"),
                CheckResult::fail("bad_check", "something broke", "try this fix"),
            ],
            is_systemd: true,
        };
        let formatted = StartupChecker::format_results(&result);
        assert!(formatted.contains("systemd"));
        assert!(formatted.contains("good_check"));
        assert!(formatted.contains("bad_check"));
        assert!(formatted.contains("something broke"));
        assert!(formatted.contains("try this fix"));
    }
}
