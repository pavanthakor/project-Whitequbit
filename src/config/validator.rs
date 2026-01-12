//! Configuration Validator - Schema validation
//!
//! Validates configuration values and reports errors.


use super::{AgentConfig, ConfigError};

/// Configuration validator
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate the entire configuration
    pub fn validate(config: &AgentConfig) -> Result<(), ConfigError> {
        Self::validate_paths(config)?;
        Self::validate_security(config)?;
        Self::validate_logging(config)?;
        Self::validate_events(config)?;
        Self::validate_actions(config)?;
        Self::validate_rollback(config)?;

        Ok(())
    }

    /// Validate paths
    fn validate_paths(config: &AgentConfig) -> Result<(), ConfigError> {
        // WAL path parent must exist or be creatable
        if let Some(parent) = config.wal_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                tracing::warn!("WAL directory {} does not exist, will be created", parent.display());
            }
        }

        // Socket path should be in a directory
        if config.socket_path.parent().is_none() {
            return Err(ConfigError::Validation(
                "socket_path must include a directory".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate security configuration
    fn validate_security(config: &AgentConfig) -> Result<(), ConfigError> {
        let sec = &config.security;

        // Validate UID range
        if sec.target_uid == 0 {
            tracing::warn!("Running as root (uid=0) is not recommended");
        }

        // Validate sandbox config
        if sec.apply_sandbox {
            if sec.sandbox.readwrite_paths.is_empty() {
                tracing::warn!("No read-write paths configured for sandbox");
            }
        }

        // Check allowed clients
        if sec.allowed_client_uids.is_empty() && sec.allowed_client_gids.is_empty() {
            return Err(ConfigError::Validation(
                "At least one allowed_client_uid or allowed_client_gid must be specified".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate logging configuration
    fn validate_logging(config: &AgentConfig) -> Result<(), ConfigError> {
        let log = &config.logging;

        // Validate log level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&log.level.to_lowercase().as_str()) {
            return Err(ConfigError::Validation(format!(
                "Invalid log level '{}'. Valid values: {:?}",
                log.level, valid_levels
            )));
        }

        // Validate format
        let valid_formats = ["json", "text", "pretty"];
        if !valid_formats.contains(&log.format.to_lowercase().as_str()) {
            return Err(ConfigError::Validation(format!(
                "Invalid log format '{}'. Valid values: {:?}",
                log.format, valid_formats
            )));
        }

        // Check that at least one output is enabled
        if !log.stdout && !log.file {
            return Err(ConfigError::Validation(
                "At least one logging output (stdout or file) must be enabled".to_string(),
            ));
        }

        // Validate file settings if file logging is enabled
        if log.file {
            if log.max_size_mb == 0 {
                return Err(ConfigError::Validation(
                    "max_size_mb must be greater than 0".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate event configuration
    fn validate_events(config: &AgentConfig) -> Result<(), ConfigError> {
        let events = &config.events;

        if events.max_queue_size == 0 {
            return Err(ConfigError::Validation(
                "max_queue_size must be greater than 0".to_string(),
            ));
        }

        if events.max_queue_size > 100000 {
            tracing::warn!("max_queue_size is very large ({}), may cause memory issues", events.max_queue_size);
        }

        if events.rate_limit == 0 {
            return Err(ConfigError::Validation(
                "rate_limit must be greater than 0".to_string(),
            ));
        }

        if events.max_payload_size > 10 * 1024 * 1024 {
            tracing::warn!("max_payload_size is very large ({}), may cause memory issues", events.max_payload_size);
        }

        Ok(())
    }

    /// Validate action configuration
    fn validate_actions(config: &AgentConfig) -> Result<(), ConfigError> {
        let actions = &config.actions;

        if actions.default_timeout == 0 {
            return Err(ConfigError::Validation(
                "default_timeout must be greater than 0".to_string(),
            ));
        }

        if actions.max_timeout < actions.default_timeout {
            return Err(ConfigError::Validation(
                "max_timeout must be >= default_timeout".to_string(),
            ));
        }

        if actions.max_concurrent == 0 {
            return Err(ConfigError::Validation(
                "max_concurrent must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate rollback configuration
    fn validate_rollback(config: &AgentConfig) -> Result<(), ConfigError> {
        let rollback = &config.rollback;

        if rollback.max_wal_size_mb == 0 {
            return Err(ConfigError::Validation(
                "max_wal_size_mb must be greater than 0".to_string(),
            ));
        }

        if rollback.enable_checkpoints {
            if rollback.checkpoint_interval == 0 {
                return Err(ConfigError::Validation(
                    "checkpoint_interval must be greater than 0".to_string(),
                ));
            }

            if rollback.max_checkpoints == 0 {
                return Err(ConfigError::Validation(
                    "max_checkpoints must be greater than 0".to_string(),
                ));
            }
        }

        if rollback.max_retries == 0 {
            tracing::warn!("max_retries is 0, compensation actions will not be retried");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_config() -> AgentConfig {
        let mut config = AgentConfig::default();
        config.security.allowed_client_uids = vec![0];
        config.logging.file = true;
        config.logging.stdout = false;
        config
    }

    #[test]
    fn test_valid_config() {
        let config = make_valid_config();
        assert!(ConfigValidator::validate(&config).is_ok());
    }

    #[test]
    fn test_invalid_log_level() {
        let mut config = make_valid_config();
        config.logging.level = "invalid".to_string();
        assert!(ConfigValidator::validate(&config).is_err());
    }

    #[test]
    fn test_no_allowed_clients() {
        let mut config = make_valid_config();
        config.security.allowed_client_uids = vec![];
        config.security.allowed_client_gids = vec![];
        assert!(ConfigValidator::validate(&config).is_err());
    }

    #[test]
    fn test_invalid_timeout() {
        let mut config = make_valid_config();
        config.actions.max_timeout = 10;
        config.actions.default_timeout = 60;
        assert!(ConfigValidator::validate(&config).is_err());
    }
}
