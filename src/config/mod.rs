//! Configuration module - Agent configuration loading and validation
//!
//! Handles configuration file parsing and runtime configuration.

mod loader;
mod validator;

pub use loader::ConfigLoader;
pub use validator::ConfigValidator;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::security::SandboxConfig;

/// Errors from configuration operations
#[derive(Error, Debug)]
pub enum ConfigError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Parse error
    #[error("Parse error: {0}")]
    Parse(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Main agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Path to the configuration file
    #[serde(skip)]
    pub config_path: PathBuf,

    /// Path to the WAL file
    pub wal_path: PathBuf,

    /// Path to the audit log
    pub audit_path: PathBuf,

    /// Path to the IPC socket
    pub socket_path: PathBuf,

    /// Path to the PID file
    pub pid_path: PathBuf,

    /// Security configuration
    pub security: SecurityConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Event handling configuration
    pub events: EventConfig,

    /// Action execution configuration
    pub actions: ActionConfig,

    /// Rollback configuration
    pub rollback: RollbackConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("/etc/whitequbit/agent.toml"),
            wal_path: PathBuf::from("/var/lib/whitequbit/wal"),
            audit_path: PathBuf::from("/var/log/whitequbit/audit.log"),
            socket_path: PathBuf::from("/var/run/whitequbit/agent.sock"),
            pid_path: PathBuf::from("/var/run/whitequbit/agent.pid"),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            events: EventConfig::default(),
            actions: ActionConfig::default(),
            rollback: RollbackConfig::default(),
        }
    }
}

impl AgentConfig {
    /// Load configuration from a file
    pub fn load(path: &PathBuf) -> Result<Self, ConfigError> {
        ConfigLoader::load(path)
    }

    /// Load configuration from a string
    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        ConfigLoader::from_str(content)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        ConfigValidator::validate(self)
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Target UID to run as
    pub target_uid: u32,

    /// Target GID to run as
    pub target_gid: u32,

    /// Whether to drop privileges
    pub drop_privileges: bool,

    /// Whether to apply sandbox
    pub apply_sandbox: bool,

    /// Sandbox configuration
    pub sandbox: SandboxConfig,

    /// Allowed UIDs for IPC clients
    pub allowed_client_uids: Vec<u32>,

    /// Allowed GIDs for IPC clients
    pub allowed_client_gids: Vec<u32>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            target_uid: 65534, // nobody
            target_gid: 65534, // nogroup
            drop_privileges: true,
            apply_sandbox: true,
            sandbox: SandboxConfig::default(),
            allowed_client_uids: vec![0], // Only root by default
            allowed_client_gids: vec![],
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,

    /// Log format (json, text)
    pub format: String,

    /// Whether to log to stdout
    pub stdout: bool,

    /// Whether to log to file
    pub file: bool,

    /// Log file path
    pub file_path: PathBuf,

    /// Maximum log file size in MB
    pub max_size_mb: u64,

    /// Number of log files to retain
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            stdout: false,
            file: true,
            file_path: PathBuf::from("/var/log/whitequbit/agent.log"),
            max_size_mb: 100,
            max_files: 5,
        }
    }
}

/// Event handling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventConfig {
    /// Maximum events to queue
    pub max_queue_size: usize,

    /// Rate limit (events per minute per client)
    pub rate_limit: u32,

    /// Rate limit window in seconds
    pub rate_limit_window: u64,

    /// Maximum event payload size in bytes
    pub max_payload_size: usize,

    /// Connection timeout in seconds
    pub connection_timeout: u64,

    /// Read timeout in seconds
    pub read_timeout: u64,
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 1000,
            rate_limit: 100,
            rate_limit_window: 60,
            max_payload_size: 65536, // 64KB
            connection_timeout: 30,
            read_timeout: 60,
        }
    }
}

/// Action execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ActionConfig {
    /// Default action timeout in seconds
    pub default_timeout: u64,

    /// Maximum action timeout in seconds
    pub max_timeout: u64,

    /// Maximum concurrent actions
    pub max_concurrent: usize,

    /// Whether to use sandbox for action execution
    pub sandbox_actions: bool,

    /// Dry run mode (don't actually execute actions)
    pub dry_run: bool,
}

impl Default for ActionConfig {
    fn default() -> Self {
        Self {
            default_timeout: 30,
            max_timeout: 300,
            max_concurrent: 10,
            sandbox_actions: true,
            dry_run: false,
        }
    }
}

/// Rollback configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RollbackConfig {
    /// Maximum WAL size in MB before compaction
    pub max_wal_size_mb: u64,

    /// Whether to create checkpoints
    pub enable_checkpoints: bool,

    /// Checkpoint interval (number of committed actions)
    pub checkpoint_interval: u64,

    /// Maximum checkpoints to retain
    pub max_checkpoints: usize,

    /// Checkpoint directory
    pub checkpoint_dir: PathBuf,

    /// Maximum retries for compensation actions
    pub max_retries: usize,

    /// Delay between retries in milliseconds
    pub retry_delay_ms: u64,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            max_wal_size_mb: 100,
            enable_checkpoints: true,
            checkpoint_interval: 100,
            max_checkpoints: 5,
            checkpoint_dir: PathBuf::from("/var/lib/whitequbit/checkpoints"),
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }
}
