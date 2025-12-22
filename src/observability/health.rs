//! Health - Health check and status reporting
//!
//! Provides health status for the agent and its components.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::RwLock;

/// Health status of a component
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Component is healthy
    Healthy,
    /// Component is degraded but functional
    Degraded,
    /// Component is unhealthy
    Unhealthy,
    /// Health status is unknown
    Unknown,
}

impl HealthStatus {
    /// Check if the status is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }

    /// Check if the status is at least functional
    pub fn is_functional(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

/// Health status of an individual component
#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Health status
    pub status: HealthStatus,
    /// Optional message
    pub message: Option<String>,
    /// Last check time (ISO 8601)
    pub last_check: String,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
}

impl ComponentHealth {
    /// Create a healthy component status
    pub fn healthy(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Healthy,
            message: None,
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms: None,
        }
    }

    /// Create an unhealthy component status
    pub fn unhealthy(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms: None,
        }
    }

    /// Create a degraded component status
    pub fn degraded(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Degraded,
            message: Some(message.into()),
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms: None,
        }
    }

    /// Set the response time
    pub fn with_response_time(mut self, duration: Duration) -> Self {
        self.response_time_ms = Some(duration.as_millis() as u64);
        self
    }
}

/// Overall health check result
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheckResult {
    /// Overall health status
    pub status: HealthStatus,
    /// Version of the agent
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Individual component health
    pub components: Vec<ComponentHealth>,
}

impl HealthCheckResult {
    /// Create a new health check result
    pub fn new(uptime: Duration) -> Self {
        Self {
            status: HealthStatus::Unknown,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: uptime.as_secs(),
            components: Vec::new(),
        }
    }

    /// Add a component health check
    pub fn add_component(&mut self, health: ComponentHealth) {
        self.components.push(health);
    }

    /// Compute overall status from component statuses
    pub fn compute_overall_status(&mut self) {
        if self.components.is_empty() {
            self.status = HealthStatus::Unknown;
            return;
        }

        // Overall status is the worst of all components
        let mut has_unhealthy = false;
        let mut has_degraded = false;

        for component in &self.components {
            match component.status {
                HealthStatus::Unhealthy => has_unhealthy = true,
                HealthStatus::Degraded => has_degraded = true,
                _ => {}
            }
        }

        self.status = if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };
    }
}

/// Trait for components that can report their health
pub trait HealthReporter: Send + Sync {
    /// Get the component name
    fn name(&self) -> &str;

    /// Check the health of this component
    fn check_health(&self) -> ComponentHealth;
}

/// Health check coordinator
pub struct HealthCheck {
    /// Registered health reporters
    reporters: RwLock<Vec<Arc<dyn HealthReporter>>>,
    /// Start time for uptime calculation
    started_at: Instant,
    /// Cached health result
    cached_result: RwLock<Option<(Instant, HealthCheckResult)>>,
    /// Cache TTL
    cache_ttl: Duration,
}

impl HealthCheck {
    /// Create a new health check coordinator
    pub fn new() -> Self {
        Self {
            reporters: RwLock::new(Vec::new()),
            started_at: Instant::now(),
            cached_result: RwLock::new(None),
            cache_ttl: Duration::from_secs(5),
        }
    }

    /// Set the cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Register a health reporter
    pub async fn register(&self, reporter: Arc<dyn HealthReporter>) {
        let mut reporters = self.reporters.write().await;
        reporters.push(reporter);
    }

    /// Perform a health check
    pub async fn check(&self) -> HealthCheckResult {
        // Check cache
        {
            let cache = self.cached_result.read().await;
            if let Some((cached_at, result)) = cache.as_ref() {
                if cached_at.elapsed() < self.cache_ttl {
                    return result.clone();
                }
            }
        }

        // Perform fresh check
        let uptime = self.started_at.elapsed();
        let mut result = HealthCheckResult::new(uptime);

        let reporters = self.reporters.read().await;
        for reporter in reporters.iter() {
            let start = Instant::now();
            let mut health = reporter.check_health();
            health = health.with_response_time(start.elapsed());
            result.add_component(health);
        }

        result.compute_overall_status();

        // Update cache
        {
            let mut cache = self.cached_result.write().await;
            *cache = Some((Instant::now(), result.clone()));
        }

        result
    }

    /// Quick liveness check (just returns if the process is responsive)
    pub fn liveness(&self) -> bool {
        true
    }

    /// Readiness check (is the agent ready to accept work)
    pub async fn readiness(&self) -> bool {
        let result = self.check().await;
        result.status.is_functional()
    }
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockReporter {
        name: String,
        healthy: bool,
    }

    impl HealthReporter for MockReporter {
        fn name(&self) -> &str {
            &self.name
        }

        fn check_health(&self) -> ComponentHealth {
            if self.healthy {
                ComponentHealth::healthy(&self.name)
            } else {
                ComponentHealth::unhealthy(&self.name, "Test failure")
            }
        }
    }

    #[tokio::test]
    async fn test_health_check() {
        let health = HealthCheck::new();

        health
            .register(Arc::new(MockReporter {
                name: "test1".to_string(),
                healthy: true,
            }))
            .await;

        health
            .register(Arc::new(MockReporter {
                name: "test2".to_string(),
                healthy: true,
            }))
            .await;

        let result = health.check().await;
        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.components.len(), 2);
    }

    #[tokio::test]
    async fn test_unhealthy_component() {
        let health = HealthCheck::new();

        health
            .register(Arc::new(MockReporter {
                name: "healthy".to_string(),
                healthy: true,
            }))
            .await;

        health
            .register(Arc::new(MockReporter {
                name: "unhealthy".to_string(),
                healthy: false,
            }))
            .await;

        let result = health.check().await;
        assert_eq!(result.status, HealthStatus::Unhealthy);
    }
}
