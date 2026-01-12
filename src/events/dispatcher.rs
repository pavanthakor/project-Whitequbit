//! Event Dispatcher - Routes events to handlers
//!
//! Collects events from multiple sources and dispatches them to handlers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;


use super::{Event, EventError};

/// Event dispatcher that collects and routes events
pub struct EventDispatcher {
    /// Channel for receiving events
    event_rx: mpsc::Receiver<Event>,
    /// Channel sender (cloned to sources)
    event_tx: mpsc::Sender<Event>,
    /// Whether to accept new events
    accepting: Arc<AtomicBool>,
    /// Handles to source tasks
    source_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl EventDispatcher {
    /// Create a new event dispatcher with the given channel size
    pub fn new(channel_size: usize) -> Self {
        let (event_tx, event_rx) = mpsc::channel(channel_size);
        let accepting = Arc::new(AtomicBool::new(true));

        Self {
            event_rx,
            event_tx,
            accepting,
            source_handles: Vec::new(),
        }
    }

    /// Create with default settings
    pub fn with_defaults() -> Self {
        Self::new(1000)
    }

    /// Get a sender for submitting events
    pub fn sender(&self) -> mpsc::Sender<Event> {
        self.event_tx.clone()
    }

    /// Submit an event directly
    pub async fn submit(&self, event: Event) -> Result<(), EventError> {
        if !self.accepting.load(Ordering::SeqCst) {
            return Err(EventError::DispatcherStopped);
        }

        self.event_tx
            .send(event)
            .await
            .map_err(|_| EventError::ChannelClosed)?;

        Ok(())
    }

    /// Get the next event
    pub async fn next(&mut self) -> Option<Event> {
        self.event_rx.recv().await
    }

    /// Check if the dispatcher is accepting events
    pub fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::SeqCst)
    }

    /// Stop accepting new events
    pub fn stop_accepting(&self) {
        tracing::info!("Event dispatcher stopping event acceptance");
        self.accepting.store(false, Ordering::SeqCst);
    }

    /// Drain remaining events (with timeout)
    /// 
    /// This method attempts to drain any remaining events from the channel
    /// before shutdown. It uses a two-tier timeout approach:
    /// - Overall deadline: total time to spend draining
    /// - Per-event timeout: time to wait for each individual event (100ms)
    /// 
    /// This prevents waiting the full timeout when the channel is empty.
    pub async fn drain(&mut self, timeout: std::time::Duration) -> Vec<Event> {
        let mut events = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        // Short timeout per-event to detect empty channel quickly
        let per_event_timeout = std::time::Duration::from_millis(100);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Use the smaller of per_event_timeout or remaining time
            let wait_time = remaining.min(per_event_timeout);

            match tokio::time::timeout(wait_time, self.event_rx.recv()).await {
                Ok(Some(event)) => events.push(event),
                Ok(None) => break, // Channel closed
                Err(_) => {
                    // If we got nothing in per_event_timeout, channel is likely empty
                    // Break out rather than waiting the full deadline
                    break;
                }
            }
        }

        tracing::debug!("Drained {} events during shutdown", events.len());
        events
    }

    /// Shutdown the dispatcher
    pub async fn shutdown(self) {
        tracing::info!("Shutting down event dispatcher");

        // Wait for source tasks to complete
        for handle in self.source_handles {
            let _ = handle.await;
        }

        // Close the channel
        drop(self.event_tx);

        tracing::info!("Event dispatcher shutdown complete");
    }
}

/// Builder for creating event dispatchers
#[allow(dead_code)]
pub struct EventDispatcherBuilder {
    channel_size: usize,
}

impl EventDispatcherBuilder {
    /// Create a new builder
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            channel_size: 1000,
        }
    }

    /// Set the channel buffer size
    #[allow(dead_code)]
    pub fn channel_size(mut self, size: usize) -> Self {
        self.channel_size = size;
        self
    }

    /// Build the dispatcher
    #[allow(dead_code)]
    pub fn build(self) -> EventDispatcher {
        EventDispatcher::new(self.channel_size)
    }
}

impl Default for EventDispatcherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::source::SystemEventType;
    use crate::events::EventType;

    #[tokio::test]
    async fn test_event_submission() {
        let mut dispatcher = EventDispatcher::with_defaults();

        let event = Event::new(
            EventType::System(SystemEventType::Heartbeat),
            serde_json::Value::Null,
        );

        dispatcher.submit(event.clone()).await.unwrap();

        let received = dispatcher.next().await.unwrap();
        assert!(received.id().as_u128() > 0);
    }

    #[tokio::test]
    async fn test_stop_accepting() {
        let dispatcher = EventDispatcher::with_defaults();

        assert!(dispatcher.is_accepting());
        dispatcher.stop_accepting();
        assert!(!dispatcher.is_accepting());

        let event = Event::new(
            EventType::System(SystemEventType::Heartbeat),
            serde_json::Value::Null,
        );

        let result = dispatcher.submit(event).await;
        assert!(result.is_err());
    }
}
