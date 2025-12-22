//! Observability module - Metrics, health monitoring, and security snapshots
//!
//! Provides runtime metrics collection, health status reporting,
//! security posture snapshots, and deterministic security versioning
//! for the agent daemon.

mod health;
mod metrics;
pub mod snapshot;
pub mod versioning;

pub use health::{HealthCheck, HealthStatus, ComponentHealth};
pub use metrics::{Metrics, MetricsSnapshot, Counter, Gauge};
pub use snapshot::{
    SecuritySnapshot, SnapshotBuilder, SnapshotCollector, SnapshotConfig,
    SnapshotDiff, SnapshotError, SnapshotResult,
    // Port types
    OpenPort, PortProtocol, PortState, PortSummary,
    // Firewall types
    FirewallRuleSummary, FirewallSummary, RuleAction, TrafficDirection,
    // Service types
    CriticalService, ServiceCategory, ServiceStatus, ServicesSummary,
    // Auth types
    AuthPosture, PasswordPolicyStrength, SshHardeningLevel,
    // Collector traits
    PortCollector, FirewallCollector, ServiceCollector, AuthCollector,
};
pub use versioning::{
    SecurityVersion, VersionHash, VersionChangeType, VersionMetadata,
    VersionStore, VersionHistory, VersioningError, VersioningResult,
    VersionManager, VersionManagerConfig, VersionNotifier, VersionChangeEvent,
    VersionComparison, VersionStats, LoggingSubscriber, FileSubscriber,
};
