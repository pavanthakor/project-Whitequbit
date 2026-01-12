//! Privilege Manager - Capability and privilege management
//!
//! Handles dropping privileges after startup.



use crate::config::SecurityConfig;

use super::SecurityError;

/// Capabilities to retain after privilege drop
#[derive(Debug, Clone)]
pub struct RequiredCapabilities {
    /// CAP_NET_ADMIN - for firewall management
    pub net_admin: bool,
    /// CAP_KILL - for process/service management
    pub kill: bool,
    /// CAP_SYS_PTRACE - for process inspection (optional)
    pub sys_ptrace: bool,
}

impl Default for RequiredCapabilities {
    fn default() -> Self {
        Self {
            net_admin: true,
            kill: true,
            sys_ptrace: false,
        }
    }
}

/// Manager for privilege operations
pub struct PrivilegeManager {
    /// Target user ID to drop to
    #[allow(dead_code)]
    target_uid: u32,
    /// Target group ID to drop to
    #[allow(dead_code)]
    target_gid: u32,
    /// Capabilities to retain
    capabilities: RequiredCapabilities,
}

impl PrivilegeManager {
    /// Create a new privilege manager from config
    pub fn new(config: &SecurityConfig) -> Result<Self, SecurityError> {
        Ok(Self {
            target_uid: config.target_uid,
            target_gid: config.target_gid,
            capabilities: RequiredCapabilities::default(),
        })
    }

    /// Create with specific user/group
    pub fn with_user(uid: u32, gid: u32) -> Self {
        Self {
            target_uid: uid,
            target_gid: gid,
            capabilities: RequiredCapabilities::default(),
        }
    }

    /// Set required capabilities
    pub fn with_capabilities(mut self, caps: RequiredCapabilities) -> Self {
        self.capabilities = caps;
        self
    }

    /// Check if we're running as root
    #[cfg(unix)]
    pub fn is_root() -> bool {
        nix::unistd::geteuid().is_root()
    }

    /// Check if we're running as root (non-Unix fallback)
    #[cfg(not(unix))]
    pub fn is_root() -> bool {
        false
    }

    /// Drop privileges to the target user/group
    #[cfg(unix)]
    pub fn drop_privileges(&self) -> Result<(), SecurityError> {
        use nix::unistd::{setgid, setgroups, setuid, Gid, Uid};

        if !Self::is_root() {
            tracing::warn!("Not running as root, skipping privilege drop");
            return Ok(());
        }

        tracing::info!(
            "Dropping privileges to uid={} gid={}",
            self.target_uid, self.target_gid
        );

        // First, set up capabilities to keep
        self.setup_capabilities()?;

        // Clear supplementary groups
        setgroups(&[]).map_err(|e| {
            SecurityError::Privilege(format!("Failed to clear supplementary groups: {}", e))
        })?;
        tracing::debug!("Cleared supplementary groups");

        // Set GID first (while still root)
        setgid(Gid::from_raw(self.target_gid)).map_err(|e| {
            SecurityError::Privilege(format!("Failed to set gid: {}", e))
        })?;
        tracing::debug!("Set GID to {}", self.target_gid);

        // Set UID last
        setuid(Uid::from_raw(self.target_uid)).map_err(|e| {
            SecurityError::Privilege(format!("Failed to set uid: {}", e))
        })?;
        tracing::debug!("Set UID to {}", self.target_uid);

        // Finalize capabilities (drop bounding set)
        self.finalize_capabilities()?;

        // Set no_new_privs to prevent regaining privileges
        self.set_no_new_privs()?;

        tracing::info!("Privilege drop complete");
        Ok(())
    }

    /// Drop privileges (non-Unix fallback)
    #[cfg(not(unix))]
    pub fn drop_privileges(&self) -> Result<(), SecurityError> {
        tracing::warn!("Privilege dropping not supported on this platform");
        Ok(())
    }

    /// Set up capabilities before dropping privileges
    #[cfg(all(unix, target_os = "linux"))]
    fn setup_capabilities(&self) -> Result<(), SecurityError> {
        use caps::{CapSet, Capability, CapsHashSet};

        // Build the set of capabilities to keep
        let mut keep = CapsHashSet::new();

        if self.capabilities.net_admin {
            keep.insert(Capability::CAP_NET_ADMIN);
        }
        if self.capabilities.kill {
            keep.insert(Capability::CAP_KILL);
        }
        if self.capabilities.sys_ptrace {
            keep.insert(Capability::CAP_SYS_PTRACE);
        }

        // Keep SETUID/SETGID to drop privileges
        keep.insert(Capability::CAP_SETUID);
        keep.insert(Capability::CAP_SETGID);

        // Set ambient capabilities (so they survive execve)
        for cap in &keep {
            caps::raise(None, CapSet::Ambient, *cap)
                .map_err(|e| SecurityError::Privilege(format!("Failed to raise ambient {}: {}", cap, e)))?;
        }

        tracing::debug!("Set up capabilities: {:?}", keep);
        Ok(())
    }

    /// Set up capabilities (non-Linux fallback)
    #[allow(dead_code)]
    #[cfg(not(all(unix, target_os = "linux")))]
    fn setup_capabilities(&self) -> Result<(), SecurityError> {
        tracing::debug!("Capability management not supported on this platform");
        Ok(())
    }

    /// Finalize capabilities after dropping privileges
    #[allow(dead_code)]
    #[cfg(all(unix, target_os = "linux"))]
    fn finalize_capabilities(&self) -> Result<(), SecurityError> {
        use caps::{CapSet, Capability};

        // Drop SETUID/SETGID now that we've dropped privileges
        caps::drop(None, CapSet::Effective, Capability::CAP_SETUID)
            .map_err(|e| SecurityError::Privilege(format!("Failed to drop CAP_SETUID: {}", e)))?;
        caps::drop(None, CapSet::Effective, Capability::CAP_SETGID)
            .map_err(|e| SecurityError::Privilege(format!("Failed to drop CAP_SETGID: {}", e)))?;

        caps::drop(None, CapSet::Permitted, Capability::CAP_SETUID)
            .map_err(|e| SecurityError::Privilege(format!("Failed to drop permitted CAP_SETUID: {}", e)))?;
        caps::drop(None, CapSet::Permitted, Capability::CAP_SETGID)
            .map_err(|e| SecurityError::Privilege(format!("Failed to drop permitted CAP_SETGID: {}", e)))?;

        tracing::debug!("Finalized capabilities");
        Ok(())
    }

    /// Finalize capabilities (non-Linux fallback)
    #[allow(dead_code)]
    #[cfg(not(all(unix, target_os = "linux")))]
    fn finalize_capabilities(&self) -> Result<(), SecurityError> {
        Ok(())
    }

    /// Set PR_SET_NO_NEW_PRIVS to prevent privilege escalation
    #[allow(dead_code)]
    #[cfg(all(unix, target_os = "linux"))]
    fn set_no_new_privs(&self) -> Result<(), SecurityError> {
        use libc::{prctl, PR_SET_NO_NEW_PRIVS};

        // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is a simple flag set operation
        // that is always safe to call. It prevents the process from gaining new
        // privileges through execve.
        let result = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if result != 0 {
            return Err(SecurityError::Privilege(
                "Failed to set PR_SET_NO_NEW_PRIVS".to_string(),
            ));
        }

        tracing::debug!("Set PR_SET_NO_NEW_PRIVS");
        Ok(())
    }

    /// Set PR_SET_NO_NEW_PRIVS (non-Linux fallback)
    #[allow(dead_code)]
    #[cfg(not(all(unix, target_os = "linux")))]
    fn set_no_new_privs(&self) -> Result<(), SecurityError> {
        Ok(())
    }

    /// Get the current effective UID
    #[cfg(unix)]
    pub fn current_uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    /// Get the current effective UID (non-Unix fallback)
    #[cfg(not(unix))]
    pub fn current_uid() -> u32 {
        0
    }

    /// Get the current effective GID
    #[cfg(unix)]
    pub fn current_gid() -> u32 {
        nix::unistd::getegid().as_raw()
    }

    /// Get the current effective GID (non-Unix fallback)
    #[cfg(not(unix))]
    pub fn current_gid() -> u32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_manager_creation() {
        let config = SecurityConfig {
            target_uid: 1000,
            target_gid: 1000,
            ..Default::default()
        };

        let manager = PrivilegeManager::new(&config).unwrap();
        assert_eq!(manager.target_uid, 1000);
        assert_eq!(manager.target_gid, 1000);
    }
}
