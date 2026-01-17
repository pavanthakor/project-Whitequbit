//! SSH Event Source - Monitors SSH authentication events via journald
//!
//! Linux-only module that ingests SSH authentication failures using journald.
//! Detects messages like "Failed password", "authentication failure", etc.
//! Converts log entries into structured internal Events for the agent to process.
//!
//! # Architecture
//!
//! This module reads from the systemd journal (`/run/log/journal` or `/var/log/journal`)
//! filtering for SSH-related log entries. It parses authentication failure patterns
//! and emits structured events that the agent can react to (e.g., blocking IPs).
//!
//! # Security Considerations
//!
//! - Requires read access to the journal (typically `adm` or `systemd-journal` group)
//! - Runs after privilege drop, so journal access must be granted to the target user
//! - Does not require root privileges for reading journal entries

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use crate::events::source::{ClientInfo, Event, EventId, EventPriority, EventType};
use crate::events::EventError;

/// SSH authentication event types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshEventType {
    /// Failed password authentication attempt
    FailedPassword {
        /// The username that was attempted
        username: String,
        /// The source IP address
        source_ip: IpAddr,
        /// The SSH port (usually 22)
        port: u16,
    },
    /// Invalid user attempt (user doesn't exist)
    InvalidUser {
        /// The username that was attempted
        username: String,
        /// The source IP address
        source_ip: IpAddr,
    },
    /// Too many authentication failures
    TooManyFailures {
        /// The username (if known)
        username: Option<String>,
        /// The source IP address
        source_ip: IpAddr,
    },
    /// Connection closed by remote host during auth
    ConnectionClosed {
        /// The source IP address
        source_ip: IpAddr,
    },
    /// PAM authentication failure
    PamAuthFailure {
        /// The username
        username: String,
        /// The source IP address (if available)
        source_ip: Option<IpAddr>,
    },
}

/// Parsed SSH event from journal
#[derive(Debug, Clone)]
pub struct SshEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type with details
    pub event_type: SshEventType,
    /// Raw log message
    pub raw_message: String,
    /// Journal cursor for deduplication
    pub cursor: Option<String>,
}

impl SshEvent {
    /// Convert to internal Event type
    pub fn into_event(self) -> Event {
        let description = match &self.event_type {
            SshEventType::FailedPassword { username, source_ip, port } => {
                format!(
                    "SSH failed password for user '{}' from {} port {}",
                    username, source_ip, port
                )
            }
            SshEventType::InvalidUser { username, source_ip } => {
                format!(
                    "SSH invalid user '{}' from {}",
                    username, source_ip
                )
            }
            SshEventType::TooManyFailures { username, source_ip } => {
                format!(
                    "SSH too many authentication failures{} from {}",
                    username.as_ref().map(|u| format!(" for '{}'", u)).unwrap_or_default(),
                    source_ip
                )
            }
            SshEventType::ConnectionClosed { source_ip } => {
                format!("SSH connection closed by {} during authentication", source_ip)
            }
            SshEventType::PamAuthFailure { username, source_ip } => {
                format!(
                    "PAM authentication failure for user '{}'{}",
                    username,
                    source_ip.map(|ip| format!(" from {}", ip)).unwrap_or_default()
                )
            }
        };

        // Determine priority based on event type
        let priority = match &self.event_type {
            SshEventType::TooManyFailures { .. } => EventPriority::High,
            SshEventType::FailedPassword { .. } | SshEventType::InvalidUser { .. } => {
                EventPriority::Normal
            }
            _ => EventPriority::Low,
        };

        // Get source IP for metadata
        let source_ip = self.source_ip();

        Event::new(
            EventType::Custom("ssh_auth".to_string()),
            description,
            serde_json::json!({
                "event_type": format!("{:?}", self.event_type),
                "source_ip": source_ip.map(|ip| ip.to_string()),
                "timestamp": self.timestamp.to_rfc3339(),
                "raw_message": self.raw_message,
            }),
        )
        .with_priority(priority)
        .with_client(ClientInfo {
            id: "journald".to_string(),
            principal: "system".to_string(),
            pid: None,
            uid: None,
            gid: None,
            remote_addr: source_ip.map(|ip| ip.to_string()),
        })
    }

    /// Extract source IP from the event
    pub fn source_ip(&self) -> Option<IpAddr> {
        match &self.event_type {
            SshEventType::FailedPassword { source_ip, .. } => Some(*source_ip),
            SshEventType::InvalidUser { source_ip, .. } => Some(*source_ip),
            SshEventType::TooManyFailures { source_ip, .. } => Some(*source_ip),
            SshEventType::ConnectionClosed { source_ip } => Some(*source_ip),
            SshEventType::PamAuthFailure { source_ip, .. } => *source_ip,
        }
    }
}

/// Configuration for the SSH event source
#[derive(Debug, Clone)]
pub struct SshEventSourceConfig {
    /// Whether to enable the SSH event source
    pub enabled: bool,
    /// Threshold for blocking an IP (failed attempts)
    pub block_threshold: u32,
    /// Window for counting failures (in seconds)
    pub window_seconds: u64,
    /// Whether to follow journal in real-time
    pub follow: bool,
    /// Filter for specific SSH units (e.g., "sshd.service")
    pub unit_filter: Option<String>,
}

impl Default for SshEventSourceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_threshold: 5,
            window_seconds: 300, // 5 minutes
            follow: true,
            unit_filter: Some("sshd.service".to_string()),
        }
    }
}

/// Failure tracking for an IP address
#[derive(Debug, Clone)]
struct IpFailureState {
    /// Number of failures in the current window
    count: u32,
    /// Timestamp of first failure in window
    window_start: DateTime<Utc>,
    /// Usernames attempted
    usernames: Vec<String>,
}

/// SSH Event Source - Monitors SSH authentication events
///
/// This source reads from the systemd journal and emits events for SSH
/// authentication failures. It can be used to implement automatic IP blocking.
pub struct SshEventSource {
    /// Configuration
    config: SshEventSourceConfig,
    /// Sender for events
    event_tx: broadcast::Sender<Event>,
    /// Failure tracking per IP
    failure_tracker: Arc<RwLock<HashMap<IpAddr, IpFailureState>>>,
    /// Shutdown signal
    shutdown: broadcast::Receiver<()>,
}

impl SshEventSource {
    /// Create a new SSH event source
    pub fn new(
        config: SshEventSourceConfig,
        event_tx: broadcast::Sender<Event>,
        shutdown: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            config,
            event_tx,
            failure_tracker: Arc::new(RwLock::new(HashMap::new())),
            shutdown,
        }
    }

    /// Start monitoring SSH events
    ///
    /// This spawns a background task that reads from journald and emits events.
    /// Returns immediately after spawning.
    pub async fn start(mut self) -> Result<(), EventError> {
        if !self.config.enabled {
            tracing::info!("SSH event source disabled");
            return Ok(());
        }

        tracing::info!("Starting SSH event source");

        // Build journalctl command
        let mut cmd = Command::new("journalctl");
        cmd.args(["--output=json", "--no-pager"]);

        // Add unit filter if configured
        if let Some(ref unit) = self.config.unit_filter {
            cmd.args(["--unit", unit]);
        }

        // Follow mode for real-time monitoring
        if self.config.follow {
            cmd.args(["--follow", "--since=now"]);
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        let mut child = cmd.spawn().map_err(|e| {
            tracing::error!(error = %e, "Failed to spawn journalctl");
            EventError::Io(e)
        })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            EventError::InvalidFormat("Failed to get journalctl stdout".to_string())
        })?;

        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        // Process journal entries
        loop {
            tokio::select! {
                biased;

                // Check for shutdown
                _ = self.shutdown.recv() => {
                    tracing::info!("SSH event source shutting down");
                    let _ = child.kill().await;
                    break;
                }

                // Read next line
                line_result = lines.next_line() => {
                    match line_result {
                        Ok(Some(line)) => {
                            if let Some(event) = self.parse_journal_entry(&line).await {
                                // Track failure
                                self.track_failure(&event).await;

                                // Send event
                                let internal_event = event.into_event();
                                if self.event_tx.send(internal_event).is_err() {
                                    tracing::warn!("Event channel closed");
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            // EOF - journalctl exited
                            if !self.config.follow {
                                break;
                            }
                            // In follow mode, this shouldn't happen
                            tracing::warn!("journalctl exited unexpectedly");
                            break;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Error reading from journalctl");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse a journal entry and extract SSH events
    async fn parse_journal_entry(&self, line: &str) -> Option<SshEvent> {
        // Parse JSON from journald
        let entry: serde_json::Value = serde_json::from_str(line).ok()?;

        // Get message
        let message = entry.get("MESSAGE")?.as_str()?;

        // Get timestamp
        let timestamp = entry
            .get("__REALTIME_TIMESTAMP")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|us| {
                DateTime::from_timestamp(us / 1_000_000, ((us % 1_000_000) * 1000) as u32)
                    .unwrap_or_else(Utc::now)
            })
            .unwrap_or_else(Utc::now);

        // Get cursor for deduplication
        let cursor = entry.get("__CURSOR").and_then(|v| v.as_str()).map(String::from);

        // Try to parse different SSH failure patterns
        if let Some(event_type) = self.parse_failed_password(message) {
            return Some(SshEvent {
                timestamp,
                event_type,
                raw_message: message.to_string(),
                cursor,
            });
        }

        if let Some(event_type) = self.parse_invalid_user(message) {
            return Some(SshEvent {
                timestamp,
                event_type,
                raw_message: message.to_string(),
                cursor,
            });
        }

        if let Some(event_type) = self.parse_too_many_failures(message) {
            return Some(SshEvent {
                timestamp,
                event_type,
                raw_message: message.to_string(),
                cursor,
            });
        }

        if let Some(event_type) = self.parse_pam_failure(message) {
            return Some(SshEvent {
                timestamp,
                event_type,
                raw_message: message.to_string(),
                cursor,
            });
        }

        None
    }

    /// Parse "Failed password" messages
    /// Example: "Failed password for root from 192.168.1.100 port 22 ssh2"
    fn parse_failed_password(&self, message: &str) -> Option<SshEventType> {
        if !message.contains("Failed password") {
            return None;
        }

        // Pattern: "Failed password for [invalid user] <user> from <ip> port <port>"
        let parts: Vec<&str> = message.split_whitespace().collect();

        // Find "from" and "port" positions
        let from_pos = parts.iter().position(|&p| p == "from")?;
        let port_pos = parts.iter().position(|&p| p == "port")?;

        // Extract IP and port
        let ip_str = parts.get(from_pos + 1)?;
        let port_str = parts.get(port_pos + 1)?;

        let source_ip = IpAddr::from_str(ip_str).ok()?;
        let port = port_str.parse::<u16>().unwrap_or(22);

        // Extract username (between "for" and "from")
        let for_pos = parts.iter().position(|&p| p == "for")?;
        let username_start = for_pos + 1;
        
        // Skip "invalid user" if present
        let username_start = if parts.get(username_start) == Some(&"invalid")
            && parts.get(username_start + 1) == Some(&"user")
        {
            username_start + 2
        } else {
            username_start
        };

        let username = parts
            .get(username_start..from_pos)
            .map(|s| s.join(" "))
            .unwrap_or_else(|| "unknown".to_string());

        Some(SshEventType::FailedPassword {
            username,
            source_ip,
            port,
        })
    }

    /// Parse "Invalid user" messages
    /// Example: "Invalid user admin from 192.168.1.100 port 22"
    fn parse_invalid_user(&self, message: &str) -> Option<SshEventType> {
        if !message.contains("Invalid user") {
            return None;
        }

        let parts: Vec<&str> = message.split_whitespace().collect();

        // Find "from" position
        let from_pos = parts.iter().position(|&p| p == "from")?;

        // Extract IP
        let ip_str = parts.get(from_pos + 1)?;
        let source_ip = IpAddr::from_str(ip_str).ok()?;

        // Extract username (between "Invalid user" and "from")
        let user_pos = parts.iter().position(|&p| p == "user")?;
        let username = parts
            .get(user_pos + 1..from_pos)
            .map(|s| s.join(" "))
            .unwrap_or_else(|| "unknown".to_string());

        Some(SshEventType::InvalidUser { username, source_ip })
    }

    /// Parse "Too many authentication failures" messages
    fn parse_too_many_failures(&self, message: &str) -> Option<SshEventType> {
        if !message.contains("Too many authentication failures") {
            return None;
        }

        let parts: Vec<&str> = message.split_whitespace().collect();

        // Try to find IP address in the message
        let source_ip = parts
            .iter()
            .find_map(|p| IpAddr::from_str(p.trim_matches(|c| c == '[' || c == ']')).ok())?;

        // Try to extract username
        let username = if message.contains("for ") {
            let for_pos = parts.iter().position(|&p| p == "for")?;
            parts.get(for_pos + 1).map(|s| s.to_string())
        } else {
            None
        };

        Some(SshEventType::TooManyFailures { username, source_ip })
    }

    /// Parse PAM authentication failure messages
    fn parse_pam_failure(&self, message: &str) -> Option<SshEventType> {
        if !message.contains("pam_unix") || !message.contains("authentication failure") {
            return None;
        }

        // Pattern: "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.100 user=root"
        let parts: Vec<&str> = message.split_whitespace().collect();

        // Extract user
        let username = parts
            .iter()
            .find(|p| p.starts_with("user="))
            .map(|p| p.strip_prefix("user=").unwrap_or("unknown").to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract rhost (remote host)
        let source_ip = parts
            .iter()
            .find(|p| p.starts_with("rhost="))
            .and_then(|p| p.strip_prefix("rhost="))
            .and_then(|s| IpAddr::from_str(s).ok());

        Some(SshEventType::PamAuthFailure { username, source_ip })
    }

    /// Track failure count per IP
    async fn track_failure(&self, event: &SshEvent) {
        let Some(source_ip) = event.source_ip() else {
            return;
        };

        let username = match &event.event_type {
            SshEventType::FailedPassword { username, .. } => Some(username.clone()),
            SshEventType::InvalidUser { username, .. } => Some(username.clone()),
            SshEventType::PamAuthFailure { username, .. } => Some(username.clone()),
            _ => None,
        };

        let mut tracker = self.failure_tracker.write().await;
        let window_duration = Duration::from_secs(self.config.window_seconds);

        let state = tracker.entry(source_ip).or_insert_with(|| IpFailureState {
            count: 0,
            window_start: event.timestamp,
            usernames: Vec::new(),
        });

        // Check if we're still within the window
        let window_elapsed = event
            .timestamp
            .signed_duration_since(state.window_start)
            .to_std()
            .unwrap_or(Duration::ZERO);

        if window_elapsed > window_duration {
            // Reset window
            state.count = 1;
            state.window_start = event.timestamp;
            state.usernames.clear();
            if let Some(ref u) = username {
                state.usernames.push(u.clone());
            }
        } else {
            // Increment within window
            state.count += 1;
            if let Some(ref u) = username {
                if !state.usernames.contains(u) {
                    state.usernames.push(u.clone());
                }
            }
        }

        // Check threshold
        if state.count >= self.config.block_threshold {
            tracing::warn!(
                ip = %source_ip,
                failures = state.count,
                usernames = ?state.usernames,
                "IP exceeded failure threshold - should be blocked"
            );
        }
    }

    /// Get current failure stats for an IP
    pub async fn get_failure_stats(&self, ip: &IpAddr) -> Option<(u32, Vec<String>)> {
        let tracker = self.failure_tracker.read().await;
        tracker.get(ip).map(|s| (s.count, s.usernames.clone()))
    }

    /// Clear failure tracking for an IP
    pub async fn clear_failures(&self, ip: &IpAddr) {
        let mut tracker = self.failure_tracker.write().await;
        tracker.remove(ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_failed_password() {
        let source = SshEventSource {
            config: SshEventSourceConfig::default(),
            event_tx: broadcast::channel(16).0,
            failure_tracker: Arc::new(RwLock::new(HashMap::new())),
            shutdown: broadcast::channel(1).1,
        };

        let msg = "Failed password for root from 192.168.1.100 port 22 ssh2";
        let result = source.parse_failed_password(msg);

        assert!(result.is_some());
        match result.unwrap() {
            SshEventType::FailedPassword {
                username,
                source_ip,
                port,
            } => {
                assert_eq!(username, "root");
                assert_eq!(source_ip.to_string(), "192.168.1.100");
                assert_eq!(port, 22);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_parse_failed_password_invalid_user() {
        let source = SshEventSource {
            config: SshEventSourceConfig::default(),
            event_tx: broadcast::channel(16).0,
            failure_tracker: Arc::new(RwLock::new(HashMap::new())),
            shutdown: broadcast::channel(1).1,
        };

        let msg = "Failed password for invalid user admin from 10.0.0.1 port 55555 ssh2";
        let result = source.parse_failed_password(msg);

        assert!(result.is_some());
        match result.unwrap() {
            SshEventType::FailedPassword {
                username,
                source_ip,
                port,
            } => {
                assert_eq!(username, "admin");
                assert_eq!(source_ip.to_string(), "10.0.0.1");
                assert_eq!(port, 55555);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_parse_invalid_user() {
        let source = SshEventSource {
            config: SshEventSourceConfig::default(),
            event_tx: broadcast::channel(16).0,
            failure_tracker: Arc::new(RwLock::new(HashMap::new())),
            shutdown: broadcast::channel(1).1,
        };

        let msg = "Invalid user admin from 192.168.1.100 port 22";
        let result = source.parse_invalid_user(msg);

        assert!(result.is_some());
        match result.unwrap() {
            SshEventType::InvalidUser { username, source_ip } => {
                assert_eq!(username, "admin");
                assert_eq!(source_ip.to_string(), "192.168.1.100");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_parse_pam_failure() {
        let source = SshEventSource {
            config: SshEventSourceConfig::default(),
            event_tx: broadcast::channel(16).0,
            failure_tracker: Arc::new(RwLock::new(HashMap::new())),
            shutdown: broadcast::channel(1).1,
        };

        let msg = "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.100 user=root";
        let result = source.parse_pam_failure(msg);

        assert!(result.is_some());
        match result.unwrap() {
            SshEventType::PamAuthFailure { username, source_ip } => {
                assert_eq!(username, "root");
                assert_eq!(source_ip.unwrap().to_string(), "192.168.1.100");
            }
            _ => panic!("Wrong event type"),
        }
    }
}
