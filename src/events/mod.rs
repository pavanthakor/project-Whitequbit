//! Events module - Event sources and dispatching
//!
//! Provides event-driven architecture for the agent.

#[cfg(unix)]
mod credentials;
mod dispatcher;
#[cfg(unix)]
mod ipc;
mod signals;
mod source;

#[cfg(unix)]
pub use credentials::{IpcAuthError, IpcAuthPolicy, PeerCredentials};
pub use dispatcher::EventDispatcher;
#[cfg(unix)]
pub use ipc::IpcEventSource;
pub use signals::{Signal, SignalHandler};
pub use source::{
    ClientInfo, Event, EventId, EventPriority, EventType, FirewallEventType, ServiceEventType,
    SystemEventType,
};

use thiserror::Error;

/// Errors from event operations
#[derive(Error, Debug)]
pub enum EventError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid event format
    #[error("Invalid event format: {0}")]
    InvalidFormat(String),

    /// Event source closed
    #[error("Event source closed")]
    SourceClosed,

    /// Authentication required
    #[error("Authentication required")]
    AuthRequired,

    /// Rate limited
    #[error("Rate limited: {0}")]
    RateLimited(String),

    /// Timeout
    #[error("Timeout waiting for event")]
    Timeout,

    /// Dispatcher stopped
    #[error("Event dispatcher stopped")]
    DispatcherStopped,

    /// Channel closed
    #[error("Event channel closed")]
    ChannelClosed,
}
