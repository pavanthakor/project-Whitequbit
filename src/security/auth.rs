//! Authentication Manager - Client authentication
//!
//! Verifies client identity using peer credentials, certificates, or tokens.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};


use crate::events::ClientInfo;

use super::SecurityError;

/// Authentication method
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Unix peer credentials (uid/gid)
    PeerCredentials,
    /// Pre-shared token
    Token,
    /// TLS client certificate
    Certificate,
    /// No authentication (dangerous!)
    None,
}

/// Authenticated client information
#[derive(Debug, Clone)]
pub struct ClientAuth {
    /// Client identifier
    pub client_id: String,
    /// Authentication method used
    pub method: AuthMethod,
    /// Unix user ID (if available)
    pub uid: Option<u32>,
    /// Unix group ID (if available)
    pub gid: Option<u32>,
    /// Groups the client belongs to
    pub groups: Vec<String>,
    /// Roles assigned to this client
    pub roles: Vec<String>,
    /// When the authentication was performed
    pub authenticated_at: DateTime<Utc>,
    /// Expiration time (for tokens)
    pub expires_at: Option<DateTime<Utc>>,
}

impl ClientAuth {
    /// Check if authentication has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    /// Check if client has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if client is in a specific group
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }
}

/// Configuration for allowed clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Allowed authentication methods
    pub allowed_methods: Vec<AuthMethod>,
    /// Allowed UIDs (for peer credentials)
    pub allowed_uids: Vec<u32>,
    /// Allowed GIDs (for peer credentials)
    pub allowed_gids: Vec<u32>,
    /// Token to UID/role mapping
    pub tokens: HashMap<String, TokenConfig>,
    /// Whether to allow root (uid=0)
    pub allow_root: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allowed_methods: vec![AuthMethod::PeerCredentials],
            allowed_uids: vec![0], // Root by default
            allowed_gids: vec![0],
            tokens: HashMap::new(),
            allow_root: true,
        }
    }
}

/// Token configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Roles assigned to this token
    pub roles: Vec<String>,
    /// Optional UID to associate
    pub uid: Option<u32>,
    /// Expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

/// Manager for client authentication
pub struct AuthManager {
    config: AuthConfig,
}

impl AuthManager {
    /// Create a new auth manager with default config
    pub fn new() -> Self {
        Self {
            config: AuthConfig::default(),
        }
    }

    /// Create with specific config
    pub fn with_config(config: AuthConfig) -> Self {
        Self { config }
    }

    /// Authenticate a client using peer credentials
    pub fn authenticate_peer(&self, client_info: &ClientInfo) -> Result<ClientAuth, SecurityError> {
        if !self.config.allowed_methods.contains(&AuthMethod::PeerCredentials) {
            return Err(SecurityError::Authentication(
                "Peer credentials authentication not allowed".to_string(),
            ));
        }

        let uid = client_info.uid.ok_or_else(|| {
            SecurityError::Authentication("No UID in client info".to_string())
        })?;

        let gid = client_info.gid.ok_or_else(|| {
            SecurityError::Authentication("No GID in client info".to_string())
        })?;

        // Check if UID is allowed
        let uid_allowed = self.config.allowed_uids.contains(&uid)
            || (uid == 0 && self.config.allow_root);

        if !uid_allowed {
            tracing::warn!("Authentication denied for uid={}", uid);
            return Err(SecurityError::Authentication(format!(
                "UID {} not in allowed list",
                uid
            )));
        }

        // Check if GID is allowed
        let gid_allowed = self.config.allowed_gids.contains(&gid)
            || self.config.allowed_gids.is_empty();

        if !gid_allowed {
            tracing::warn!("Authentication denied for gid={}", gid);
            return Err(SecurityError::Authentication(format!(
                "GID {} not in allowed list",
                gid
            )));
        }

        // Look up groups for the UID
        let groups = self.get_user_groups(uid);

        // Assign roles based on UID/GID
        let roles = self.get_roles_for_uid(uid);

        tracing::info!("Client authenticated: uid={} gid={}", uid, gid);

        Ok(ClientAuth {
            client_id: client_info.id.clone(),
            method: AuthMethod::PeerCredentials,
            uid: Some(uid),
            gid: Some(gid),
            groups,
            roles,
            authenticated_at: Utc::now(),
            expires_at: None,
        })
    }

    /// Authenticate a client using a token
    pub fn authenticate_token(
        &self,
        client_id: &str,
        token: &str,
    ) -> Result<ClientAuth, SecurityError> {
        if !self.config.allowed_methods.contains(&AuthMethod::Token) {
            return Err(SecurityError::Authentication(
                "Token authentication not allowed".to_string(),
            ));
        }

        // Hash the token for lookup (don't store plaintext tokens in config)
        let token_hash = Self::hash_token(token);

        let token_config = self.config.tokens.get(&token_hash).ok_or_else(|| {
            tracing::warn!("Invalid token for client {}", client_id);
            SecurityError::Authentication("Invalid token".to_string())
        })?;

        // Check expiration
        if let Some(expires) = token_config.expires_at {
            if Utc::now() > expires {
                return Err(SecurityError::Authentication("Token expired".to_string()));
            }
        }

        tracing::info!("Client {} authenticated with token", client_id);

        Ok(ClientAuth {
            client_id: client_id.to_string(),
            method: AuthMethod::Token,
            uid: token_config.uid,
            gid: None,
            groups: Vec::new(),
            roles: token_config.roles.clone(),
            authenticated_at: Utc::now(),
            expires_at: token_config.expires_at,
        })
    }

    /// Get groups for a user
    #[cfg(unix)]
    fn get_user_groups(&self, uid: u32) -> Vec<String> {
        // In production, we'd use getgrouplist(3)
        // For now, return empty
        Vec::new()
    }

    #[cfg(not(unix))]
    fn get_user_groups(&self, _uid: u32) -> Vec<String> {
        Vec::new()
    }

    /// Get roles for a UID
    fn get_roles_for_uid(&self, uid: u32) -> Vec<String> {
        let mut roles = Vec::new();

        if uid == 0 {
            roles.push("admin".to_string());
            roles.push("operator".to_string());
        } else {
            roles.push("operator".to_string());
        }

        roles
    }

    /// Hash a token for storage/lookup
    fn hash_token(token: &str) -> String {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(token.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Add an allowed UID
    pub fn allow_uid(&mut self, uid: u32) {
        if !self.config.allowed_uids.contains(&uid) {
            self.config.allowed_uids.push(uid);
        }
    }

    /// Add an allowed GID
    pub fn allow_gid(&mut self, gid: u32) {
        if !self.config.allowed_gids.contains(&gid) {
            self.config.allowed_gids.push(gid);
        }
    }
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_manager_creation() {
        let manager = AuthManager::new();
        assert!(manager.config.allow_root);
    }

    #[test]
    fn test_client_auth_expiration() {
        let auth = ClientAuth {
            client_id: "test".to_string(),
            method: AuthMethod::Token,
            uid: None,
            gid: None,
            groups: Vec::new(),
            roles: vec!["admin".to_string()],
            authenticated_at: Utc::now(),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        };

        assert!(auth.is_expired());
    }

    #[test]
    fn test_role_check() {
        let auth = ClientAuth {
            client_id: "test".to_string(),
            method: AuthMethod::PeerCredentials,
            uid: Some(1000),
            gid: Some(1000),
            groups: Vec::new(),
            roles: vec!["admin".to_string(), "operator".to_string()],
            authenticated_at: Utc::now(),
            expires_at: None,
        };

        assert!(auth.has_role("admin"));
        assert!(!auth.has_role("superuser"));
    }
}
