//! Event Loop - Async event reactor
//!
//! Single-threaded async event loop that processes events and executes actions.
//! Never blocks; all I/O is async. Integrates with signal handling for graceful shutdown.

use std::sync::Arc;
use std::time::Duration;

use tokio::select;
use tokio::sync::broadcast;
use tracing::Instrument;

use crate::audit::AuditLogger;
use crate::events::{Event, EventDispatcher, EventType, Signal};
use crate::rollback::Journal;

use super::shutdown::ShutdownCoordinator;
use super::state_machine::{AgentState, StateMachine};
use super::CoreError;

/// Timeout for draining in-flight actions during shutdown
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval for periodic health checks
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Event loop that drives the agent
pub struct EventLoop {
    state_machine: Arc<StateMachine>,
    event_dispatcher: EventDispatcher,
    audit_logger: Arc<AuditLogger>,
    journal: Arc<Journal>,
    shutdown_coordinator: Arc<ShutdownCoordinator>,
    signal_rx: Option<broadcast::Receiver<Signal>>,
}

impl EventLoop {
    /// Create a new event loop builder
    pub fn builder() -> EventLoopBuilder {
        EventLoopBuilder::new()
    }

    /// Get a reference to the shutdown coordinator
    pub fn shutdown_coordinator(&self) -> &Arc<ShutdownCoordinator> {
        &self.shutdown_coordinator
    }

    /// Run the event loop
    pub async fn run(&mut self) -> Result<(), CoreError> {
        tracing::info!("Starting event loop");

        // Ensure we're in Ready state
        if self.state_machine.current() != AgentState::Ready {
            self.state_machine.transition_to(AgentState::Ready)?;
        }

        // Take the signal receiver
        let mut signal_rx = self.signal_rx.take();

        // Create health check interval
        let mut health_interval = tokio::time::interval(HEALTH_CHECK_INTERVAL);
        health_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            select! {
                biased;

                // Handle shutdown signal (highest priority)
                _ = self.shutdown_coordinator.wait_for_shutdown() => {
                    tracing::info!("Shutdown signal received from coordinator");
                    break;
                }

                // Handle OS signals
                signal = async {
                    match &mut signal_rx {
                        Some(rx) => rx.recv().await.ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(sig) = signal {
                        if self.handle_signal(sig).await? {
                            break;
                        }
                    }
                }

                // Handle incoming events
                event = self.event_dispatcher.next() => {
                    match event {
                        Some(event) => {
                            let event_id = event.id();
                            if let Err(e) = self.handle_event(event)
                                .instrument(tracing::debug_span!("handle_event", %event_id))
                                .await
                            {
                                tracing::error!(error = %e, %event_id, "Error handling event");
                            }
                        }
                        None => {
                            tracing::debug!("Event dispatcher closed");
                            break;
                        }
                    }
                }

                // Periodic health check
                _ = health_interval.tick() => {
                    self.perform_health_check().await;
                }
            }
        }

        // Initiate graceful shutdown
        self.shutdown().await?;

        Ok(())
    }

    /// Handle an OS signal
    async fn handle_signal(&self, signal: Signal) -> Result<bool, CoreError> {
        match signal {
            Signal::Terminate | Signal::Interrupt => {
                tracing::info!(?signal, "Received termination signal");
                self.shutdown_coordinator.initiate_shutdown();
                Ok(true)
            }
            Signal::Hangup => {
                tracing::info!("Received SIGHUP, config reload requested");
                // TODO: Implement config reload
                Ok(false)
            }
            Signal::User1 => {
                tracing::debug!("Received SIGUSR1");
                // Used for supervisor communication
                Ok(false)
            }
            Signal::User2 => {
                tracing::debug!("Received SIGUSR2");
                // Reserved for future use
                Ok(false)
            }
        }
    }

    /// Handle a single event
    async fn handle_event(&self, event: Event) -> Result<(), CoreError> {
        let event_type = event.event_type_enum().clone();
        tracing::debug!(?event_type, "Handling event");

        // Log event received
        if let Err(e) = self.audit_logger.log_event_received(&event).await {
            tracing::warn!(error = %e, "Failed to log event");
        }

        // Process based on event type
        match &event_type {
            EventType::System(system_type) => {
                self.handle_system_event(system_type).await?;
            }
            EventType::Firewall(firewall_type) => {
                tracing::debug!(?firewall_type, "Firewall event");
                self.handle_action_event(&event).await?;
            }
            EventType::Service(service_type) => {
                tracing::debug!(?service_type, "Service event");
                self.handle_action_event(&event).await?;
            }
            EventType::Custom(name) => {
                tracing::debug!(name, "Custom event");
            }
        }

        Ok(())
    }

    /// Handle system events
    async fn handle_system_event(
        &self,
        system_type: &crate::events::SystemEventType,
    ) -> Result<(), CoreError> {
        use crate::events::SystemEventType;

        match system_type {
            SystemEventType::Shutdown => {
                tracing::info!("Shutdown event received");
                self.shutdown_coordinator.initiate_shutdown();
            }
            SystemEventType::ConfigReload | SystemEventType::Reload => {
                tracing::info!("Config reload event received");
                // TODO: Implement config reload
            }
            SystemEventType::Heartbeat => {
                tracing::debug!("Heartbeat received");
            }
            SystemEventType::Status => {
                tracing::info!("Status check requested");
            }
            SystemEventType::HealthCheck => {
                tracing::debug!("Health check received");
                self.perform_health_check().await;
            }
        }

        Ok(())
    }
    /// Handle action events (firewall, service, etc.)
    async fn handle_action_event(&self, event: &Event) -> Result<(), CoreError> {
        let action_id = crate::actions::ActionId::new();
        let action_type = format!("{:?}", event.event_type());

        // Log action prepared
        if let Err(e) = self
            .audit_logger
            .log_action_prepared(&action_id.to_string(), &action_type, None)
            .await
        {
            tracing::warn!(error = %e, "Failed to log action prepared");
        }

        // Prepare journal entry
        let entry_id = self
            .journal
            .prepare(
                action_id.clone(),
                &action_type,
                event.payload().clone(),
                serde_json::json!({"action_type": action_type, "undo": true}),
            )
            .await
            .map_err(|e| CoreError::Internal(format!("Journal error: {}", e)))?;

        // Execute the action through the executor
        // The actual execution is delegated to the action executor which handles
        // timeouts, sandboxing, and error recovery
        let execution_result = self.execute_action(event).await;

        match execution_result {
            Ok(()) => {
                // Commit the journal entry on success
                self.journal
                    .commit(entry_id)
                    .await
                    .map_err(|e| CoreError::Internal(format!("Journal commit error: {}", e)))?;

                tracing::info!(%action_id, "Action completed successfully");
            }
            Err(e) => {
                // Mark rollback needed on failure
                tracing::warn!(%action_id, error = %e, "Action failed, initiating rollback");

                if let Err(rollback_err) = self.journal.mark_rolled_back(entry_id).await {
                    tracing::error!(
                        %action_id,
                        error = %rollback_err,
                        "Failed to mark entry as rolled back"
                    );
                }

                return Err(e);
            }
        }

        Ok(())
    }

    /// Execute an action (to be implemented by action executor)
    async fn execute_action(&self, _event: &Event) -> Result<(), CoreError> {
        // This would be delegated to the ActionExecutor in a full implementation
        // For now, we acknowledge the action
        Ok(())
    }

    /// Perform periodic health check
    async fn perform_health_check(&self) {
        tracing::debug!("Performing health check");

        // Check state machine
        let state = self.state_machine.current();
        tracing::debug!(?state, "Current agent state");

        // Check journal health
        let uncommitted = self.journal.get_uncommitted().await;
        if !uncommitted.is_empty() {
            tracing::warn!(
                count = uncommitted.len(),
                "Uncommitted journal entries detected"
            );
        }

        // Check event dispatcher
        if !self.event_dispatcher.is_accepting() {
            tracing::warn!("Event dispatcher is not accepting events");
        }
    }

    /// Graceful shutdown
    async fn shutdown(&mut self) -> Result<(), CoreError> {
        tracing::info!("Beginning graceful shutdown");

        // Transition to draining state
        self.state_machine.transition_to(AgentState::Draining)?;
        self.shutdown_coordinator.begin_draining();

        // Stop accepting new events
        self.event_dispatcher.stop_accepting();

        // Drain remaining events with timeout
        let remaining = self.event_dispatcher.drain(DRAIN_TIMEOUT).await;
        if !remaining.is_empty() {
            tracing::warn!(count = remaining.len(), "Events dropped during shutdown");
        }

        // Flush journal
        if let Err(e) = self.journal.flush().await {
            tracing::error!(error = %e, "Failed to flush journal");
        }

        // Flush audit log
        if let Err(e) = self.audit_logger.flush().await {
            tracing::error!(error = %e, "Failed to flush audit log");
        }

        // Transition to stopped
        self.state_machine.transition_to(AgentState::Stopped)?;
        self.shutdown_coordinator.mark_complete();

        tracing::info!("Shutdown complete");
        Ok(())
    }
}

/// Builder for EventLoop
pub struct EventLoopBuilder {
    state_machine: Option<Arc<StateMachine>>,
    event_dispatcher: Option<EventDispatcher>,
    audit_logger: Option<Arc<AuditLogger>>,
    journal: Option<Arc<Journal>>,
    shutdown_coordinator: Option<Arc<ShutdownCoordinator>>,
    signal_rx: Option<broadcast::Receiver<Signal>>,
}

impl EventLoopBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            state_machine: None,
            event_dispatcher: None,
            audit_logger: None,
            journal: None,
            shutdown_coordinator: None,
            signal_rx: None,
        }
    }

    /// Set the state machine
    pub fn state_machine(mut self, sm: Arc<StateMachine>) -> Self {
        self.state_machine = Some(sm);
        self
    }

    /// Set the event dispatcher
    pub fn event_dispatcher(mut self, dispatcher: EventDispatcher) -> Self {
        self.event_dispatcher = Some(dispatcher);
        self
    }

    /// Set the audit logger
    pub fn audit_logger(mut self, logger: Arc<AuditLogger>) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Set the journal
    pub fn journal(mut self, journal: Arc<Journal>) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Set the shutdown coordinator
    pub fn shutdown_coordinator(mut self, coordinator: Arc<ShutdownCoordinator>) -> Self {
        self.shutdown_coordinator = Some(coordinator);
        self
    }

    /// Set the signal receiver
    pub fn signal_receiver(mut self, rx: broadcast::Receiver<Signal>) -> Self {
        self.signal_rx = Some(rx);
        self
    }

    /// Build the event loop
    ///
    /// # Panics
    ///
    /// Panics if required components are not set.
    pub fn build(self) -> EventLoop {
        EventLoop {
            state_machine: self.state_machine.expect("state_machine is required"),
            event_dispatcher: self.event_dispatcher.expect("event_dispatcher is required"),
            audit_logger: self.audit_logger.expect("audit_logger is required"),
            journal: self.journal.expect("journal is required"),
            shutdown_coordinator: self
                .shutdown_coordinator
                .unwrap_or_else(|| Arc::new(ShutdownCoordinator::new())),
            signal_rx: self.signal_rx,
        }
    }
}

impl Default for EventLoopBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::StateMachine;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_event_loop_creation() {
        let dir = tempdir().unwrap();
        let audit_path = dir.path().join("audit.log");
        let wal_path = dir.path().join("journal.wal");

        let state_machine = Arc::new(StateMachine::new());
        let dispatcher = EventDispatcher::with_defaults();
        let audit_logger = Arc::new(AuditLogger::new(&audit_path).unwrap());
        let journal = Arc::new(Journal::new(&wal_path).unwrap());

        let _event_loop = EventLoop::builder()
            .state_machine(state_machine)
            .event_dispatcher(dispatcher)
            .audit_logger(audit_logger)
            .journal(journal)
            .build();
    }

    #[tokio::test]
    async fn test_shutdown_in_select_loop() {
        // Test that wait_for_shutdown works correctly in a select! loop
        // This validates the shutdown coordinator works when repeatedly polled
        let shutdown = Arc::new(ShutdownCoordinator::new());
        let shutdown_clone = shutdown.clone();
        
        // Spawn task to initiate shutdown after delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown_clone.initiate_shutdown();
        });
        
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        let mut ticks = 0;
        
        loop {
            select! {
                biased;
                
                _ = shutdown.wait_for_shutdown() => {
                    break;
                }
                
                _ = interval.tick() => {
                    ticks += 1;
                }
            }
        }
        
        assert!(ticks > 0, "Should have some ticks before shutdown");
        assert!(shutdown.is_shutdown_initiated(), "Shutdown should be initiated");
    }

    #[tokio::test]
    async fn test_event_loop_shutdown() {
        let dir = tempdir().unwrap();
        let audit_path = dir.path().join("audit.log");
        let wal_path = dir.path().join("journal.wal");

        let state_machine = Arc::new(StateMachine::new());
        state_machine.transition_to(AgentState::Ready).unwrap();

        let dispatcher = EventDispatcher::with_defaults();
        let audit_logger = Arc::new(AuditLogger::new(&audit_path).unwrap());
        let journal = Arc::new(Journal::new(&wal_path).unwrap());
        let shutdown = Arc::new(ShutdownCoordinator::new());

        let mut event_loop = EventLoop::builder()
            .state_machine(state_machine)
            .event_dispatcher(dispatcher)
            .audit_logger(audit_logger)
            .journal(journal)
            .shutdown_coordinator(shutdown.clone())
            .build();

        // Trigger shutdown after a short delay
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            shutdown_clone.initiate_shutdown();
        });

        // Run should complete after shutdown
        let result = tokio::time::timeout(Duration::from_secs(5), event_loop.run()).await;
        assert!(result.is_ok(), "Event loop should complete");
    }
}
