//! Metrics - Runtime metrics collection
//!
//! Thread-safe metrics collection for observability.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;

/// A monotonic counter
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    /// Create a new counter
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the counter by 1
    pub fn inc(&self) {
        self.add(1);
    }

    /// Add a value to the counter
    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Get the current value
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A gauge that can go up and down
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicI64,
}

impl Gauge {
    /// Create a new gauge
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the gauge to a value
    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    /// Increment the gauge by 1
    pub fn inc(&self) {
        self.add(1);
    }

    /// Decrement the gauge by 1
    pub fn dec(&self) {
        self.sub(1);
    }

    /// Add a value to the gauge
    pub fn add(&self, n: i64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Subtract a value from the gauge
    pub fn sub(&self, n: i64) {
        self.value.fetch_sub(n, Ordering::Relaxed);
    }

    /// Get the current value
    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Agent metrics
pub struct Metrics {
    /// When the agent started
    started_at: Instant,
    /// Startup timestamp
    started_at_utc: DateTime<Utc>,

    // Event metrics
    /// Total events received
    pub events_received: Counter,
    /// Events processed successfully
    pub events_processed: Counter,
    /// Events rejected
    pub events_rejected: Counter,
    /// Events currently in queue
    pub events_queued: Gauge,

    // Action metrics
    /// Total actions executed
    pub actions_executed: Counter,
    /// Actions that succeeded
    pub actions_succeeded: Counter,
    /// Actions that failed
    pub actions_failed: Counter,
    /// Actions currently in flight
    pub actions_in_flight: Gauge,
    /// Actions rolled back
    pub actions_rolled_back: Counter,

    // System metrics
    /// Current state (as u8)
    pub current_state: Gauge,
    /// Number of connected clients
    pub connected_clients: Gauge,
    /// Recovery operations performed
    pub recoveries_performed: Counter,

    // Health metrics
    /// Last health check timestamp (unix epoch)
    pub last_health_check: AtomicU64,
    /// Health check pass count
    pub health_checks_passed: Counter,
    /// Health check fail count
    pub health_checks_failed: Counter,
}

impl Metrics {
    /// Create a new metrics instance
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            started_at_utc: Utc::now(),
            events_received: Counter::new(),
            events_processed: Counter::new(),
            events_rejected: Counter::new(),
            events_queued: Gauge::new(),
            actions_executed: Counter::new(),
            actions_succeeded: Counter::new(),
            actions_failed: Counter::new(),
            actions_in_flight: Gauge::new(),
            actions_rolled_back: Counter::new(),
            current_state: Gauge::new(),
            connected_clients: Gauge::new(),
            recoveries_performed: Counter::new(),
            last_health_check: AtomicU64::new(0),
            health_checks_passed: Counter::new(),
            health_checks_failed: Counter::new(),
        }
    }

    /// Get uptime duration
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Update last health check timestamp
    pub fn record_health_check(&self, passed: bool) {
        self.last_health_check.store(
            Utc::now().timestamp() as u64,
            Ordering::Relaxed,
        );
        if passed {
            self.health_checks_passed.inc();
        } else {
            self.health_checks_failed.inc();
        }
    }

    /// Get a snapshot of all metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_seconds: self.uptime().as_secs(),
            started_at: self.started_at_utc.to_rfc3339(),
            events_received: self.events_received.get(),
            events_processed: self.events_processed.get(),
            events_rejected: self.events_rejected.get(),
            events_queued: self.events_queued.get(),
            actions_executed: self.actions_executed.get(),
            actions_succeeded: self.actions_succeeded.get(),
            actions_failed: self.actions_failed.get(),
            actions_in_flight: self.actions_in_flight.get(),
            actions_rolled_back: self.actions_rolled_back.get(),
            current_state: self.current_state.get(),
            connected_clients: self.connected_clients.get(),
            recoveries_performed: self.recoveries_performed.get(),
            last_health_check: self.last_health_check.load(Ordering::Relaxed),
            health_checks_passed: self.health_checks_passed.get(),
            health_checks_failed: self.health_checks_failed.get(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable snapshot of metrics
#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// ISO 8601 start time
    pub started_at: String,

    /// Number of events received
    pub events_received: u64,
    /// Number of events processed
    pub events_processed: u64,
    /// Number of events rejected
    pub events_rejected: u64,
    /// Number of events currently queued
    pub events_queued: i64,

    /// Number of actions executed
    pub actions_executed: u64,
    /// Number of actions succeeded
    pub actions_succeeded: u64,
    /// Number of actions failed
    pub actions_failed: u64,
    /// Number of actions in flight
    pub actions_in_flight: i64,
    /// Number of actions rolled back
    pub actions_rolled_back: u64,

    /// Current state code
    pub current_state: i64,
    /// Number of connected clients
    pub connected_clients: i64,
    /// Number of recoveries performed
    pub recoveries_performed: u64,

    /// Timestamp of last health check
    pub last_health_check: u64,
    /// Number of passed health checks
    pub health_checks_passed: u64,
    /// Number of failed health checks
    pub health_checks_failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.add(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);

        gauge.set(10);
        assert_eq!(gauge.get(), 10);

        gauge.inc();
        assert_eq!(gauge.get(), 11);

        gauge.dec();
        assert_eq!(gauge.get(), 10);

        gauge.sub(5);
        assert_eq!(gauge.get(), 5);
    }

    #[test]
    fn test_metrics_snapshot() {
        let metrics = Metrics::new();
        metrics.events_received.add(100);
        metrics.actions_executed.add(50);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.events_received, 100);
        assert_eq!(snapshot.actions_executed, 50);
    }
}
