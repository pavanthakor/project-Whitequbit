//! Configuration Loader - File loading and parsing
//!
//! Loads configuration from TOML files.

use std::path::PathBuf;



use super::{AgentConfig, ConfigError};

/// Configuration loader
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from a file
    pub fn load(path: &PathBuf) -> Result<AgentConfig, ConfigError> {
        tracing::info!("Loading configuration from {}", path.display());

        let content = std::fs::read_to_string(path)?;
        let mut config = Self::from_str(&content)?;

        // Store the config path
        config.config_path = path.clone();

        tracing::debug!("Configuration loaded successfully");
        Ok(config)
    }

    /// Parse configuration from a string
    pub fn from_str(content: &str) -> Result<AgentConfig, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Load with environment variable overrides
    pub fn load_with_env(path: &PathBuf) -> Result<AgentConfig, ConfigError> {
        let mut config = Self::load(path)?;

        // Override with environment variables
        if let Ok(val) = std::env::var("WHITEQUBIT_LOG_LEVEL") {
            config.logging.level = val;
        }

        if let Ok(val) = std::env::var("WHITEQUBIT_DRY_RUN") {
            config.actions.dry_run = val.parse().unwrap_or(false);
        }

        if let Ok(val) = std::env::var("WHITEQUBIT_WAL_PATH") {
            config.wal_path = PathBuf::from(val);
        }

        if let Ok(val) = std::env::var("WHITEQUBIT_SOCKET_PATH") {
            config.socket_path = PathBuf::from(val);
        }

        Ok(config)
    }

    /// Create a default configuration file
    pub fn create_default_config(path: &PathBuf) -> Result<(), ConfigError> {
        let config = AgentConfig::default();
        let content = toml::to_string_pretty(&config)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, content)?;
        tracing::info!("Created default configuration at {}", path.display());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let config_str = r#"
            wal_path = "/tmp/wal"
            audit_path = "/tmp/audit.log"
            socket_path = "/tmp/agent.sock"
            pid_path = "/tmp/agent.pid"
        "#;

        let config = ConfigLoader::from_str(config_str).unwrap();
        assert_eq!(config.wal_path, PathBuf::from("/tmp/wal"));
    }

    #[test]
    fn test_parse_full_config() {
        let config_str = r#"
            wal_path = "/var/lib/whitequbit/wal"
            audit_path = "/var/log/whitequbit/audit.log"
            socket_path = "/var/run/whitequbit/agent.sock"
            pid_path = "/var/run/whitequbit/agent.pid"

            [security]
            target_uid = 1000
            target_gid = 1000
            drop_privileges = true

            [logging]
            level = "debug"
            format = "json"

            [events]
            max_queue_size = 500
            rate_limit = 50

            [actions]
            default_timeout = 60
            dry_run = true

            [rollback]
            max_retries = 5
        "#;

        let config = ConfigLoader::from_str(config_str).unwrap();
        assert_eq!(config.security.target_uid, 1000);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.events.max_queue_size, 500);
        assert!(config.actions.dry_run);
        assert_eq!(config.rollback.max_retries, 5);
    }

    #[test]
    fn test_default_values() {
        let config_str = r#"
            wal_path = "/tmp/wal"
        "#;

        let config = ConfigLoader::from_str(config_str).unwrap();

        // Check defaults are applied
        assert_eq!(config.security.target_uid, 65534);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.actions.default_timeout, 30);
    }
}
