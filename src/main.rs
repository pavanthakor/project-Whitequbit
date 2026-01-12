//! WhiteQubit Agent - Main Entry Point
//!
//! This is the main daemon process that handles security actions.
//! It performs privilege setup, crash recovery, and enters the event loop.
//!
//! # Startup Phases
//!
//! 1. Parse arguments and load configuration
//! 2. Initialize state machine and logging
//! 3. Open privileged resources (files, sockets)
//! 4. Crash recovery from WAL
//! 5. Initialize audit logging
//! 6. Drop privileges (Unix)
//! 7. Apply sandbox restrictions (Linux)
//! 8. Initialize event dispatcher and signal handler
//! 9. Run main event loop
//! 10. Graceful shutdown

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tracing::Instrument;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use whitequbit_agent::{
    audit::AuditLogger,
    config::AgentConfig,
    core::{AgentState, EventLoop, ShutdownCoordinator, StateMachine},
    events::{EventDispatcher, SignalHandler},
    rollback::{Journal, RecoveryManager},
    Result,
};

/// Default paths for the agent
#[cfg(unix)]
mod paths {
    pub const CONFIG_PATH: &str = "/etc/whitequbit/agent.toml";
    pub const WAL_PATH: &str = "/var/lib/whitequbit/wal";
    pub const AUDIT_PATH: &str = "/var/log/whitequbit/audit.log";
    pub const PID_FILE: &str = "/var/run/whitequbit/agent.pid";
    pub const SOCKET_PATH: &str = "/var/run/whitequbit/agent.sock";
}

#[cfg(windows)]
#[allow(dead_code)]
mod paths {
    pub const CONFIG_PATH: &str = "C:\\ProgramData\\whitequbit\\agent.toml";
    pub const WAL_PATH: &str = "C:\\ProgramData\\whitequbit\\wal";
    pub const AUDIT_PATH: &str = "C:\\ProgramData\\whitequbit\\audit.log";
    pub const PID_FILE: &str = "C:\\ProgramData\\whitequbit\\agent.pid";
    pub const SOCKET_PATH: &str = "\\\\.\\pipe\\whitequbit-agent";
}

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize early logging (before config is loaded)
    init_early_logging();

    // Log startup info
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        "Starting whitequbit-agent"
    );

    match run_agent().await {
        Ok(()) => {
            tracing::info!("Agent shutdown complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "Agent failed");
            ExitCode::FAILURE
        }
    }
}

/// Main agent execution flow
async fn run_agent() -> Result<()> {
    // Phase 1: Parse arguments and load configuration
    let args = parse_args();
    let config = AgentConfig::load(&args.config_path)?;

    // Validate configuration before proceeding
    config.validate()?;

    // Re-initialize logging with configuration
    init_configured_logging(&config);

    // Phase 2: Initialize state machine (starts in Init state)
    let state_machine = Arc::new(StateMachine::new());

    // Phase 3: Initialize shutdown coordinator
    let shutdown_coordinator = Arc::new(ShutdownCoordinator::new());

    // Phase 4: Open privileged resources
    tracing::info!("Opening privileged resources");
    let privileged_resources = open_privileged_resources(&config).await?;

    // Phase 5: Crash recovery - check WAL for incomplete actions
    state_machine.transition_to(AgentState::Recovering)?;
    let journal = Journal::new(&config.wal_path)?;
    let journal = Arc::new(journal);
    let recovery_manager = RecoveryManager::new(journal.clone());
    let recovery_result = recovery_manager.recover().await?;
    if recovery_result.entries_recovered > 0 {
        tracing::warn!(
            entries = recovery_result.entries_recovered,
            "Recovered incomplete actions from previous crash"
        );
    }

    // Phase 6: Initialize audit logger
    let audit_logger = AuditLogger::new(&config.audit_path)?;
    let audit_logger = Arc::new(audit_logger);
    audit_logger.log_startup(&config).await?;

    // Phase 7: Drop privileges (Unix only)
    #[cfg(unix)]
    if config.security.drop_privileges {
        use whitequbit_agent::security::PrivilegeManager;
        tracing::info!("Dropping privileges");
        let privilege_manager = PrivilegeManager::new(&config.security)?;
        privilege_manager.drop_privileges()?;
    }

    // Phase 8: Apply sandbox restrictions (Linux only)
    #[cfg(target_os = "linux")]
    if config.security.apply_sandbox {
        use whitequbit_agent::security::SandboxManager;
        tracing::info!("Applying sandbox restrictions");
        let sandbox_manager = SandboxManager::new(&config.security)?;
        sandbox_manager.apply_sandbox()?;
    }

    // Phase 9: Initialize signal handler
    let mut signal_handler = SignalHandler::new();
    let signal_rx = signal_handler.start();

    // Phase 10: Initialize event dispatcher
    let event_dispatcher = EventDispatcher::new(config.events.max_queue_size);

    // Phase 11: Transition to ready state
    state_machine.transition_to(AgentState::Ready)?;
    tracing::info!("Agent ready, entering event loop");

    // Signal readiness to supervisor
    signal_ready_to_supervisor()?;

    // Phase 12: Run the event loop with signal handling
    let mut event_loop = EventLoop::builder()
        .state_machine(state_machine)
        .event_dispatcher(event_dispatcher)
        .audit_logger(audit_logger.clone())
        .journal(journal)
        .shutdown_coordinator(shutdown_coordinator.clone())
        .signal_receiver(signal_rx)
        .build();

    // Run the event loop
    let loop_result = event_loop
        .run()
        .instrument(tracing::info_span!("event_loop"))
        .await;

    // Phase 13: Graceful shutdown
    tracing::info!("Initiating graceful shutdown");
    shutdown_coordinator.initiate_shutdown();

    // Log shutdown
    if let Err(e) = audit_logger.log_shutdown("graceful").await {
        tracing::warn!(error = %e, "Failed to log shutdown");
    }

    // Clean up signal handler
    signal_handler.stop().await;

    // Clean up privileged resources
    drop(privileged_resources);

    // Clean up PID file
    cleanup_pid_file(&config).await;

    loop_result?;
    Ok(())
}

/// Command-line arguments
struct Args {
    config_path: PathBuf,
    #[allow(dead_code)]
    foreground: bool,
    #[allow(dead_code)]
    dry_run: bool,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    
    let config_path = args
        .iter()
        .position(|a| a == "--config" || a == "-c")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(paths::CONFIG_PATH));

    let foreground = args.iter().any(|a| a == "--foreground" || a == "-f");
    let dry_run = args.iter().any(|a| a == "--dry-run" || a == "-n");

    Args {
        config_path,
        foreground,
        dry_run,
    }
}

/// Initialize logging before config is loaded
fn init_early_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .with_ansi(atty::is(atty::Stream::Stderr)),
        )
        .init();
}

/// Re-initialize logging based on configuration
fn init_configured_logging(config: &AgentConfig) {
    // Note: In production, you would use tracing-appender for file output
    // and proper log rotation. The initial subscriber cannot be replaced,
    // but we log this for observability.
    tracing::info!(
        level = %config.logging.level,
        format = %config.logging.format,
        file = %config.logging.file_path.display(),
        "Logging configuration loaded"
    );
}

/// Resources opened while running with privileges
pub struct PrivilegedResources {
    /// WAL file handle
    #[allow(dead_code)]
    pub wal_file: tokio::fs::File,
    /// IPC listener (Unix only)
    #[cfg(unix)]
    #[allow(dead_code)]
    pub ipc_listener: tokio::net::UnixListener,
}

/// Open resources that require elevated privileges
async fn open_privileged_resources(
    config: &AgentConfig,
) -> Result<PrivilegedResources> {
    

    // Create WAL directory if needed
    if let Some(parent) = config.wal_path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
            tracing::debug!(path = %parent.display(), "Created WAL directory");
        }
    }

    // Open WAL file with exclusive lock
    let wal_file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&config.wal_path)
        .await?;
    tracing::debug!(path = %config.wal_path.display(), "Opened WAL file");

    // Write PID file
    if let Some(parent) = config.pid_path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let pid = std::process::id();
    tokio::fs::write(&config.pid_path, pid.to_string()).await?;
    tracing::info!(pid = pid, path = %config.pid_path.display(), "Wrote PID file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::UnixListener;

        // Create IPC socket directory if needed
        if let Some(parent) = config.socket_path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        // Remove existing socket file
        let _ = tokio::fs::remove_file(&config.socket_path).await;

        // Bind to IPC socket
        let ipc_listener = UnixListener::bind(&config.socket_path)?;
        tracing::debug!(path = %config.socket_path.display(), "Bound IPC socket");

        // Set socket permissions (0660)
        let perms = std::fs::Permissions::from_mode(0o660);
        std::fs::set_permissions(&config.socket_path, perms)?;

        return Ok(PrivilegedResources {
            wal_file,
            ipc_listener,
        });
    }

    #[cfg(not(unix))]
    Ok(PrivilegedResources { wal_file })
}

/// Clean up PID file on shutdown
async fn cleanup_pid_file(config: &AgentConfig) {
    if let Err(e) = tokio::fs::remove_file(&config.pid_path).await {
        tracing::warn!(error = %e, path = %config.pid_path.display(), "Failed to remove PID file");
    }
}

/// Signal to supervisor that we're ready
fn signal_ready_to_supervisor() -> Result<()> {
    #[cfg(unix)]
    {
        // Send USR1 to parent process (supervisor)
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::getppid;

        let ppid = getppid();
        if ppid.as_raw() > 1 {
            let _ = kill(ppid, Signal::SIGUSR1);
        }
    }
    Ok(())
}
