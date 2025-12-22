//! WhiteQubit Supervisor - Watchdog Process
//!
//! Minimal supervisor that monitors the agent process and restarts it on failure.
//! This process is intentionally simple to minimize attack surface.

use std::process::{Child, Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESTARTS: usize = 5;
const RESTART_WINDOW: Duration = Duration::from_secs(300); // 5 minutes

fn main() -> ExitCode {
    eprintln!("[supervisor] Starting whitequbit-agent supervisor");

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let mut restart_times: Vec<Instant> = Vec::new();

    while !shutdown.load(Ordering::Relaxed) {
        // Check restart rate limiting
        let now = Instant::now();
        restart_times.retain(|t| now.duration_since(*t) < RESTART_WINDOW);

        if restart_times.len() >= MAX_RESTARTS {
            eprintln!(
                "[supervisor] Too many restarts ({} in {:?}), staying down",
                MAX_RESTARTS, RESTART_WINDOW
            );
            return ExitCode::FAILURE;
        }

        // Spawn agent process
        eprintln!("[supervisor] Spawning agent process");
        let mut child = match spawn_agent() {
            Ok(child) => child,
            Err(e) => {
                eprintln!("[supervisor] Failed to spawn agent: {}", e);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        restart_times.push(Instant::now());

        // Monitor the agent
        let exit_status = monitor_agent(&mut child, &shutdown);

        match exit_status {
            AgentExit::Clean => {
                eprintln!("[supervisor] Agent exited cleanly");
                break;
            }
            AgentExit::Crashed(code) => {
                eprintln!("[supervisor] Agent crashed with code {:?}, restarting", code);
            }
            AgentExit::Timeout => {
                eprintln!("[supervisor] Agent heartbeat timeout, killing and restarting");
                kill_agent(&mut child);
            }
            AgentExit::ShutdownRequested => {
                eprintln!("[supervisor] Shutdown requested, stopping agent");
                graceful_shutdown(&mut child);
                break;
            }
        }
    }

    eprintln!("[supervisor] Supervisor exiting");
    ExitCode::SUCCESS
}

fn spawn_agent() -> std::io::Result<Child> {
    let exe_path = std::env::current_exe()?;
    let agent_path = exe_path
        .parent()
        .map(|p| p.join("whitequbit-agent"))
        .unwrap_or_else(|| "whitequbit-agent".into());

    Command::new(agent_path)
        .args(std::env::args().skip(1))
        .spawn()
}

enum AgentExit {
    Clean,
    Crashed(Option<i32>),
    Timeout,
    ShutdownRequested,
}

fn monitor_agent(child: &mut Child, shutdown: &AtomicBool) -> AgentExit {
    let mut last_heartbeat = Instant::now();
    let mut agent_ready = false;

    loop {
        // Check for shutdown signal
        if shutdown.load(Ordering::Relaxed) {
            return AgentExit::ShutdownRequested;
        }

        // Check if agent is still running
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return AgentExit::Clean;
                } else {
                    return AgentExit::Crashed(status.code());
                }
            }
            Ok(None) => {
                // Still running
            }
            Err(e) => {
                eprintln!("[supervisor] Error checking agent status: {}", e);
                return AgentExit::Crashed(None);
            }
        }

        // Check heartbeat timeout (only after agent signals ready)
        if agent_ready && last_heartbeat.elapsed() > HEARTBEAT_TIMEOUT {
            return AgentExit::Timeout;
        }

        // TODO: Implement heartbeat mechanism via shared memory or pipe
        // For now, we just assume the agent is alive if the process is running
        last_heartbeat = Instant::now();
        agent_ready = true;

        std::thread::sleep(Duration::from_secs(1));
    }
}

fn kill_agent(child: &mut Child) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            libc::kill(child.id() as i32, libc::SIGKILL);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }

    let _ = child.wait();
}

fn graceful_shutdown(child: &mut Child) {
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
    }

    // Wait for graceful shutdown
    let start = Instant::now();
    while start.elapsed() < GRACEFUL_SHUTDOWN_TIMEOUT {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Force kill if graceful shutdown times out
    eprintln!("[supervisor] Graceful shutdown timeout, force killing");
    kill_agent(child);
}

fn setup_signal_handlers(shutdown: Arc<AtomicBool>) {
    #[cfg(unix)]
    {
        use std::thread;

        thread::spawn(move || {
            let mut signals = signal_hook::iterator::Signals::new(&[
                signal_hook::consts::SIGTERM,
                signal_hook::consts::SIGINT,
            ])
            .expect("Failed to create signal handler");

            for _ in signals.forever() {
                shutdown.store(true, Ordering::Relaxed);
                break;
            }
        });
    }

    #[cfg(not(unix))]
    {
        ctrlc::set_handler(move || {
            shutdown.store(true, Ordering::Relaxed);
        })
        .expect("Failed to set Ctrl-C handler");
    }
}
