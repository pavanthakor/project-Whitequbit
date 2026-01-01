//! IPC Credential Verification - Unix socket peer credential checks
//!
//! This module provides secure client authentication for Unix domain sockets
//! using SO_PEERCRED to verify the identity of connecting processes.

use std::os::unix::net::UnixStream;
use std::io;

use tracing::{debug, info, warn};

/// Peer credentials from a Unix socket connection
#[derive(Debug, Clone)]
pub struct PeerCredentials {
    /// Process ID of the peer
    pub pid: u32,
    /// User ID of the peer
    pub uid: u32,
    /// Group ID of the peer
    pub gid: u32,
}

impl PeerCredentials {
    /// Get credentials from a Unix stream socket
    #[cfg(target_os = "linux")]
    pub fn from_stream(stream: &UnixStream) -> io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        use std::mem::MaybeUninit;

        let fd = stream.as_raw_fd();
        let mut cred = MaybeUninit::<libc::ucred>::uninit();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

        // SAFETY: getsockopt with SO_PEERCRED is safe for Unix domain sockets.
        // The fd is valid (from UnixStream), cred is properly sized, and len
        // is correctly initialized to the size of ucred.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                cred.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };

        if result != 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: getsockopt succeeded (result == 0), so cred is now initialized
        let cred = unsafe { cred.assume_init() };
        
        Ok(Self {
            pid: cred.pid as u32,
            uid: cred.uid,
            gid: cred.gid,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn from_stream(_stream: &UnixStream) -> io::Result<Self> {
        // On non-Linux, return a placeholder
        // In production, use platform-specific methods
        Ok(Self {
            pid: 0,
            uid: 0,
            gid: 0,
        })
    }

    /// Check if the peer is running as root
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    /// Check if the peer is in a specific group
    pub fn has_group(&self, gid: u32) -> bool {
        self.gid == gid
    }
}

/// Policy for IPC client authorization
#[derive(Debug, Clone)]
pub struct IpcAuthPolicy {
    /// Allowed user IDs (empty = allow all)
    pub allowed_uids: Vec<u32>,
    /// Allowed group IDs (empty = allow all)
    pub allowed_gids: Vec<u32>,
    /// Require root for certain operations
    pub require_root_for_privileged: bool,
    /// Allow connections from any user (dangerous!)
    pub allow_any: bool,
}

impl Default for IpcAuthPolicy {
    fn default() -> Self {
        Self {
            // By default, only root and the whitequbit user can connect
            allowed_uids: vec![0], // root
            allowed_gids: vec![],
            require_root_for_privileged: true,
            allow_any: false,
        }
    }
}

impl IpcAuthPolicy {
    /// Create a permissive policy (for development only!)
    pub fn permissive() -> Self {
        warn!("Using permissive IPC auth policy - NOT FOR PRODUCTION");
        Self {
            allowed_uids: vec![],
            allowed_gids: vec![],
            require_root_for_privileged: false,
            allow_any: true,
        }
    }

    /// Create a policy that allows a specific user
    pub fn allow_user(uid: u32) -> Self {
        Self {
            allowed_uids: vec![0, uid], // root + specified user
            ..Default::default()
        }
    }

    /// Create a policy that allows a specific group
    pub fn allow_group(gid: u32) -> Self {
        Self {
            allowed_gids: vec![0, gid], // root group + specified group
            ..Default::default()
        }
    }

    /// Check if a peer is authorized to connect
    pub fn authorize(&self, creds: &PeerCredentials) -> Result<(), IpcAuthError> {
        debug!(
            "Authorizing peer: pid={}, uid={}, gid={}",
            creds.pid, creds.uid, creds.gid
        );

        // Always allow root
        if creds.is_root() {
            info!("Authorized: peer is root (pid={})", creds.pid);
            return Ok(());
        }

        // Check if any user is allowed
        if self.allow_any {
            info!("Authorized: allow_any is set (pid={})", creds.pid);
            return Ok(());
        }

        // Check allowed UIDs
        if !self.allowed_uids.is_empty() && self.allowed_uids.contains(&creds.uid) {
            info!(
                "Authorized: uid {} in allowlist (pid={})",
                creds.uid, creds.pid
            );
            return Ok(());
        }

        // Check allowed GIDs
        if !self.allowed_gids.is_empty() && self.allowed_gids.contains(&creds.gid) {
            info!(
                "Authorized: gid {} in allowlist (pid={})",
                creds.gid, creds.pid
            );
            return Ok(());
        }

        // Deny by default
        warn!(
            "Denied: peer uid={} gid={} not authorized (pid={})",
            creds.uid, creds.gid, creds.pid
        );
        Err(IpcAuthError::Unauthorized {
            uid: creds.uid,
            gid: creds.gid,
        })
    }

    /// Check if a peer can perform a privileged action
    pub fn authorize_privileged(
        &self,
        creds: &PeerCredentials,
        action_type: &str,
    ) -> Result<(), IpcAuthError> {
        // First, basic authorization
        self.authorize(creds)?;

        // Then check if privileged access is needed
        if self.require_root_for_privileged && !creds.is_root() {
            warn!(
                "Denied privileged action '{}': peer not root (uid={}, pid={})",
                action_type, creds.uid, creds.pid
            );
            return Err(IpcAuthError::PrivilegeRequired {
                action: action_type.to_string(),
            });
        }

        Ok(())
    }
}

/// Errors from IPC authentication
#[derive(Debug, thiserror::Error)]
pub enum IpcAuthError {
    /// Failed to get peer credentials
    #[error("Failed to get peer credentials: {0}")]
    CredentialError(#[from] io::Error),

    /// Peer not authorized
    #[error("Unauthorized: uid={uid} gid={gid}")]
    Unauthorized { uid: u32, gid: u32 },

    /// Privileged action requires root
    #[error("Privileged action '{action}' requires root")]
    PrivilegeRequired { action: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_allows_root() {
        let policy = IpcAuthPolicy::default();
        let root_creds = PeerCredentials {
            pid: 1234,
            uid: 0,
            gid: 0,
        };
        assert!(policy.authorize(&root_creds).is_ok());
    }

    #[test]
    fn test_default_policy_denies_regular_user() {
        let policy = IpcAuthPolicy::default();
        let user_creds = PeerCredentials {
            pid: 1234,
            uid: 1000,
            gid: 1000,
        };
        assert!(policy.authorize(&user_creds).is_err());
    }

    #[test]
    fn test_allow_user_policy() {
        let policy = IpcAuthPolicy::allow_user(1000);
        let user_creds = PeerCredentials {
            pid: 1234,
            uid: 1000,
            gid: 1000,
        };
        assert!(policy.authorize(&user_creds).is_ok());
    }

    #[test]
    fn test_privileged_requires_root() {
        let policy = IpcAuthPolicy::default();
        let user_creds = PeerCredentials {
            pid: 1234,
            uid: 1000,
            gid: 1000,
        };

        // Need to add user to allowed list first
        let policy = IpcAuthPolicy::allow_user(1000);
        
        // User can connect
        assert!(policy.authorize(&user_creds).is_ok());
        
        // But can't do privileged actions
        assert!(policy
            .authorize_privileged(&user_creds, "firewall")
            .is_err());
    }
}
