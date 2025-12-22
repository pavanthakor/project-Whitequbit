//! Signal Handler - OS signal handling
//!
//! Handles Unix signals for the agent.

use tokio::sync::broadcast;
use tracing::info;

/// Signal types that the agent handles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Terminate (SIGTERM)
    Terminate,
    /// Interrupt (SIGINT)
    Interrupt,
    /// Hangup (SIGHUP) - reload config
    Hangup,
    /// User 1 (SIGUSR1)
    User1,
    /// User 2 (SIGUSR2)
    User2,
}

/// Handler for OS signals
pub struct SignalHandler {
    /// Broadcast sender for signal notifications
    tx: broadcast::Sender<Signal>,
    /// Task handle
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl SignalHandler {
    /// Create a new signal handler
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(16);

        Self { tx, handle: None }
    }

    /// Start listening for signals
    pub fn start(&mut self) -> broadcast::Receiver<Signal> {
        let tx = self.tx.clone();
        let rx = self.tx.subscribe();

        let handle = tokio::spawn(async move {
            Self::signal_loop(tx).await;
        });

        self.handle = Some(handle);
        rx
    }

    /// Get a receiver for signals
    pub fn subscribe(&self) -> broadcast::Receiver<Signal> {
        self.tx.subscribe()
    }

    /// Signal handling loop
    #[cfg(unix)]
    async fn signal_loop(tx: broadcast::Sender<Signal>) {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to create SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to create SIGINT handler");
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to create SIGHUP handler");
        let mut sigusr1 = signal(SignalKind::user_defined1()).expect("Failed to create SIGUSR1 handler");
        let mut sigusr2 = signal(SignalKind::user_defined2()).expect("Failed to create SIGUSR2 handler");

        loop {
            let signal = tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM");
                    Signal::Terminate
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT");
                    Signal::Interrupt
                }
                _ = sighup.recv() => {
                    info!("Received SIGHUP");
                    Signal::Hangup
                }
                _ = sigusr1.recv() => {
                    debug!("Received SIGUSR1");
                    Signal::User1
                }
                _ = sigusr2.recv() => {
                    debug!("Received SIGUSR2");
                    Signal::User2
                }
            };

            if tx.send(signal).is_err() {
                debug!("No signal receivers, continuing");
            }

            // Exit loop on terminate signals
            if matches!(signal, Signal::Terminate | Signal::Interrupt) {
                break;
            }
        }

        info!("Signal handler loop exiting");
    }

    #[cfg(not(unix))]
    async fn signal_loop(tx: broadcast::Sender<Signal>) {
        // Windows signal handling
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Received Ctrl+C");
            let _ = tx.send(Signal::Interrupt);
        }
    }

    /// Stop the signal handler
    pub async fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Default for SignalHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SignalHandler {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_signal_handler_creation() {
        let handler = SignalHandler::new();
        let _rx = handler.subscribe();

        // Just verify it doesn't panic
        drop(handler);
    }
}
