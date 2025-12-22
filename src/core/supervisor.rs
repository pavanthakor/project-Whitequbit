//! Supervisor Client - Communication with the watchdog process
//!
//! Provides heartbeat functionality and status reporting to the supervisor.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::interval;
use tracing::{debug, error};

/// Heartbeat interval
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// Client for communicating with the supervisor process
pub struct SupervisorClient {
    running: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
}

impl SupervisorClient {
    /// Create a new supervisor client
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
        }
    }

    /// Start the heartbeat task
    pub fn start_heartbeat(&self) -> tokio::task::JoinHandle<()> {
        let running = self.running.clone();
        let shutdown_notify = self.shutdown_notify.clone();

        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            let mut ticker = interval(HEARTBEAT_INTERVAL);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }
                        Self::send_heartbeat().await;
                    }
                    _ = shutdown_notify.notified() => {
                        debug!("Heartbeat task shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Stop the heartbeat task
    pub fn stop_heartbeat(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_one();
    }

    /// Send a heartbeat to the supervisor
    async fn send_heartbeat() {
        // In a real implementation, this would:
        // 1. Write to a shared memory region
        // 2. Send a signal to parent
        // 3. Write to a pipe
        // For now, we just log
        debug!("Sending heartbeat to supervisor");

        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::getppid;

            let ppid = getppid();
            if ppid.as_raw() > 1 {
                // Parent is not init, send heartbeat signal
                if let Err(e) = kill(ppid, Signal::SIGUSR2) {
                    warn!("Failed to send heartbeat: {}", e);
                }
            }
        }
    }

    /// Signal to supervisor that we're ready
    pub fn signal_ready(&self) {
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::getppid;

            let ppid = getppid();
            if ppid.as_raw() > 1 {
                if let Err(e) = kill(ppid, Signal::SIGUSR1) {
                    error!("Failed to signal ready to supervisor: {}", e);
                }
            }
        }
    }

    /// Report a critical error to the supervisor
    pub fn report_critical_error(&self, message: &str) {
        error!("Critical error reported to supervisor: {}", message);
        // In a real implementation, this might write to a shared error log
        // or send a structured message to the supervisor
    }
}

impl Default for SupervisorClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SupervisorClient {
    fn drop(&mut self) {
        self.stop_heartbeat();
    }
}
