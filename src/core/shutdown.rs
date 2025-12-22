//! Shutdown Coordinator - Thread-safe shutdown orchestration
//!
//! Coordinates graceful shutdown across all components of the agent.
//! Uses atomic flags and broadcast channels for efficient notification.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Notify};
use tracing::{debug, info, warn};

/// Shutdown phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShutdownPhase {
    /// Normal operation
    Running = 0,
    /// Stop accepting new work
    StopAccepting = 1,
    /// Drain in-flight work
    Draining = 2,
    /// Force immediate shutdown
    Immediate = 3,
    /// Shutdown complete
    Complete = 4,
}

impl TryFrom<u8> for ShutdownPhase {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ShutdownPhase::Running),
            1 => Ok(ShutdownPhase::StopAccepting),
            2 => Ok(ShutdownPhase::Draining),
            3 => Ok(ShutdownPhase::Immediate),
            4 => Ok(ShutdownPhase::Complete),
            _ => Err(()),
        }
    }
}

/// Thread-safe shutdown coordinator
///
/// Provides a centralized mechanism for coordinating graceful shutdown
/// across all agent components.
pub struct ShutdownCoordinator {
    /// Current shutdown phase
    phase: AtomicU8,
    /// Whether shutdown has been initiated
    initiated: AtomicBool,
    /// Notify for shutdown signal
    notify: Notify,
    /// Watch channel for phase updates
    phase_tx: watch::Sender<ShutdownPhase>,
    /// Watch receiver (cloned to subscribers)
    phase_rx: watch::Receiver<ShutdownPhase>,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new() -> Self {
        let (phase_tx, phase_rx) = watch::channel(ShutdownPhase::Running);

        Self {
            phase: AtomicU8::new(ShutdownPhase::Running as u8),
            initiated: AtomicBool::new(false),
            notify: Notify::new(),
            phase_tx,
            phase_rx,
        }
    }

    /// Check if shutdown has been initiated
    pub fn is_shutdown_initiated(&self) -> bool {
        self.initiated.load(Ordering::SeqCst)
    }

    /// Get the current shutdown phase
    pub fn current_phase(&self) -> ShutdownPhase {
        ShutdownPhase::try_from(self.phase.load(Ordering::SeqCst))
            .unwrap_or(ShutdownPhase::Running)
    }

    /// Initiate graceful shutdown
    ///
    /// Returns true if this call initiated shutdown, false if already initiated.
    pub fn initiate_shutdown(&self) -> bool {
        let was_initiated = self.initiated.swap(true, Ordering::SeqCst);

        if !was_initiated {
            info!("Shutdown initiated");
            self.transition_phase(ShutdownPhase::StopAccepting);
            self.notify.notify_waiters();
            true
        } else {
            debug!("Shutdown already initiated");
            false
        }
    }

    /// Request immediate shutdown (skip draining)
    pub fn request_immediate(&self) {
        warn!("Immediate shutdown requested");
        self.initiated.store(true, Ordering::SeqCst);
        self.transition_phase(ShutdownPhase::Immediate);
        self.notify.notify_waiters();
    }

    /// Transition to the next shutdown phase
    fn transition_phase(&self, phase: ShutdownPhase) {
        let old_phase = self.phase.swap(phase as u8, Ordering::SeqCst);
        let old = ShutdownPhase::try_from(old_phase).unwrap_or(ShutdownPhase::Running);

        if old != phase {
            debug!(?old, new = ?phase, "Shutdown phase transition");
            let _ = self.phase_tx.send(phase);
        }
    }

    /// Begin draining phase
    pub fn begin_draining(&self) {
        if self.current_phase() == ShutdownPhase::StopAccepting {
            self.transition_phase(ShutdownPhase::Draining);
        }
    }

    /// Mark shutdown as complete
    pub fn mark_complete(&self) {
        self.transition_phase(ShutdownPhase::Complete);
    }

    /// Wait for shutdown signal
    /// 
    /// This function returns immediately if shutdown has already been initiated,
    /// otherwise it waits until initiate_shutdown() is called.
    /// 
    /// Note: This is designed to be used in a tokio::select! loop where it may be
    /// cancelled and recreated on each iteration. It uses a watch channel to ensure
    /// we don't miss the shutdown signal between iterations.
    pub async fn wait_for_shutdown(&self) {
        // First check if already initiated
        if self.is_shutdown_initiated() {
            return;
        }
        
        // Use watch channel - this correctly handles the case where we subscribe
        // after the value has already changed
        let mut rx = self.phase_rx.clone();
        
        // Check current value - if not Running, shutdown has begun
        if *rx.borrow_and_update() != ShutdownPhase::Running {
            return;
        }
        
        // Wait for change
        let _ = rx.changed().await;
    }

    /// Get a receiver for phase updates
    pub fn subscribe(&self) -> watch::Receiver<ShutdownPhase> {
        self.phase_rx.clone()
    }

    /// Wait for a specific phase with timeout
    pub async fn wait_for_phase(
        &self,
        target: ShutdownPhase,
        timeout: Duration,
    ) -> Result<(), tokio::time::error::Elapsed> {
        let mut rx = self.subscribe();

        tokio::time::timeout(timeout, async {
            loop {
                if *rx.borrow() == target || *rx.borrow() as u8 > target as u8 {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        })
        .await
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that tracks in-flight operations
///
/// Used to ensure all in-flight work completes before shutdown.
#[allow(dead_code)]
pub struct InFlightGuard {
    coordinator: Arc<ShutdownCoordinator>,
    _marker: (),
}

impl InFlightGuard {
    /// Create a new in-flight guard
    #[allow(dead_code)]
    pub fn new(coordinator: Arc<ShutdownCoordinator>) -> Option<Self> {
        // Don't allow new in-flight operations if draining or later
        if coordinator.current_phase() as u8 >= ShutdownPhase::Draining as u8 {
            return None;
        }

        Some(Self {
            coordinator,
            _marker: (),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_coordinator() {
        let coordinator = ShutdownCoordinator::new();

        assert!(!coordinator.is_shutdown_initiated());
        assert_eq!(coordinator.current_phase(), ShutdownPhase::Running);

        assert!(coordinator.initiate_shutdown());
        assert!(coordinator.is_shutdown_initiated());
        assert_eq!(coordinator.current_phase(), ShutdownPhase::StopAccepting);

        // Second initiate should return false
        assert!(!coordinator.initiate_shutdown());
    }

    #[test]
    fn test_phase_transitions() {
        let coordinator = ShutdownCoordinator::new();

        coordinator.initiate_shutdown();
        assert_eq!(coordinator.current_phase(), ShutdownPhase::StopAccepting);

        coordinator.begin_draining();
        assert_eq!(coordinator.current_phase(), ShutdownPhase::Draining);

        coordinator.mark_complete();
        assert_eq!(coordinator.current_phase(), ShutdownPhase::Complete);
    }

    #[test]
    fn test_immediate_shutdown() {
        let coordinator = ShutdownCoordinator::new();

        coordinator.request_immediate();
        assert!(coordinator.is_shutdown_initiated());
        assert_eq!(coordinator.current_phase(), ShutdownPhase::Immediate);
    }

    #[tokio::test]
    async fn test_wait_for_shutdown() {
        let coordinator = Arc::new(ShutdownCoordinator::new());
        let coord2 = coordinator.clone();

        let handle = tokio::spawn(async move {
            coord2.wait_for_shutdown().await;
            true
        });

        // Give the task time to start waiting
        tokio::time::sleep(Duration::from_millis(10)).await;

        coordinator.initiate_shutdown();

        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("timeout")
            .expect("join error");

        assert!(result);
    }
}
