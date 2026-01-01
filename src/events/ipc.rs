//! IPC Event Source - Unix socket listener
//!
//! Listens for events on a Unix domain socket.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::source::{ClientInfo, Event, EventSource, EventType};
use super::EventError;

/// Rate limiter for clients
struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Window duration
    window: Duration,
    /// Request counts per client
    counts: HashMap<String, (u32, Instant)>,
}

impl RateLimiter {
    fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            counts: HashMap::new(),
        }
    }

    fn check(&mut self, client_id: &str) -> bool {
        let now = Instant::now();

        let (count, window_start) = self
            .counts
            .entry(client_id.to_string())
            .or_insert((0, now));

        // Reset if window expired
        if now.duration_since(*window_start) > self.window {
            *count = 0;
            *window_start = now;
        }

        if *count >= self.max_requests {
            false
        } else {
            *count += 1;
            true
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.counts
            .retain(|_, (_, start)| now.duration_since(*start) <= self.window * 2);
    }
}

/// IPC event source using Unix sockets
pub struct IpcEventSource {
    /// Unix socket listener
    listener: UnixListener,
    /// Event channel
    event_tx: mpsc::Sender<Event>,
    /// Event receiver
    event_rx: mpsc::Receiver<Event>,
    /// Connected clients
    client_count: Arc<AtomicU64>,
    /// Rate limiter
    rate_limiter: Arc<tokio::sync::Mutex<RateLimiter>>,
    /// Shutdown flag
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl IpcEventSource {
    /// Create a new IPC event source
    pub fn new(listener: UnixListener) -> Self {
        let (event_tx, event_rx) = mpsc::channel(100);

        Self {
            listener,
            event_tx,
            event_rx,
            client_count: Arc::new(AtomicU64::new(0)),
            rate_limiter: Arc::new(tokio::sync::Mutex::new(RateLimiter::new(100, Duration::from_secs(60)))),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start accepting connections
    /// Note: Connection acceptance is handled by next_event() method in the EventSource trait.
    /// This method spawns a background task for cleanup and rate limit housekeeping.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        // Note: tokio::net::UnixListener cannot be cloned. Connection acceptance
        // happens in next_event(). This task handles periodic cleanup.
        let rate_limiter = self.rate_limiter.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            info!("IPC event source background task started");
            
            // Periodic cleanup loop
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                
                // Clean up expired rate limit entries
                let mut limiter = rate_limiter.lock().await;
                limiter.cleanup();
            }
        })
    }

    /// Handle a single client connection
    async fn handle_client(
        stream: UnixStream,
        event_tx: mpsc::Sender<Event>,
        client_count: Arc<AtomicU64>,
        rate_limiter: Arc<tokio::sync::Mutex<RateLimiter>>,
    ) {
        let client_id = format!("client-{}", client_count.fetch_add(1, Ordering::SeqCst));
        info!("New IPC client connected: {}", client_id);

        // Get peer credentials
        let client_info = Self::get_peer_credentials(&stream, &client_id);

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();

            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // Connection closed
                    debug!("Client {} disconnected", client_id);
                    break;
                }
                Ok(_) => {
                    // Check rate limit
                    {
                        let mut limiter = rate_limiter.lock().await;
                        if !limiter.check(&client_id) {
                            warn!("Client {} rate limited", client_id);
                            let _ = writer.write_all(b"ERROR: rate limited\n").await;
                            continue;
                        }
                    }

                    // Parse the event
                    match Self::parse_message(&line, client_info.clone()) {
                        Ok(event) => {
                            debug!("Received event {:?} from {}", event.id(), client_id);

                            // Send acknowledgment
                            let ack = format!("OK: {}\n", event.id());
                            let _ = writer.write_all(ack.as_bytes()).await;

                            // Forward event
                            if event_tx.send(event).await.is_err() {
                                error!("Event channel closed");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse message from {}: {}", client_id, e);
                            let error_msg = format!("ERROR: {}\n", e);
                            let _ = writer.write_all(error_msg.as_bytes()).await;
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from client {}: {}", client_id, e);
                    break;
                }
            }
        }

        info!("Client {} handler exiting", client_id);
    }

    /// Get peer credentials from Unix socket
    fn get_peer_credentials(stream: &UnixStream, client_id: &str) -> ClientInfo {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            use std::os::fd::BorrowedFd;

            let fd = stream.as_raw_fd();

            // Try to get peer credentials using nix's getsockopt
            // SAFETY: We know the fd is valid because it comes from a live UnixStream
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
            let creds = nix::sys::socket::getsockopt(
                &borrowed_fd,
                nix::sys::socket::sockopt::PeerCredentials,
            );

            match creds {
                Ok(cred) => ClientInfo {
                    id: client_id.to_string(),
                    // Principal derived from UID for local Unix socket peers
                    principal: format!("uid:{}", cred.uid()),
                    pid: Some(cred.pid() as u32),
                    uid: Some(cred.uid()),
                    gid: Some(cred.gid()),
                    remote_addr: None,
                },
                Err(_) => ClientInfo {
                    id: client_id.to_string(),
                    principal: "unknown".to_string(),
                    pid: None,
                    uid: None,
                    gid: None,
                    remote_addr: None,
                },
            }
        }

        #[cfg(not(unix))]
        {
            ClientInfo {
                id: client_id.to_string(),
                principal: "unknown".to_string(),
                pid: None,
                uid: None,
                gid: None,
                remote_addr: None,
            }
        }
    }

    /// Parse a message into an event
    fn parse_message(line: &str, client: ClientInfo) -> Result<Event, EventError> {
        let line = line.trim();

        if line.is_empty() {
            return Err(EventError::InvalidFormat("empty message".to_string()));
        }

        // Try to parse as JSON
        let parsed: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| EventError::InvalidFormat(format!("invalid JSON: {}", e)))?;

        // Extract event type
        let event_type_str = parsed["type"]
            .as_str()
            .ok_or_else(|| EventError::InvalidFormat("missing 'type' field".to_string()))?;

        let event_type = Self::parse_event_type(event_type_str)?;

        // Create event
        let event = Event::new(event_type, parsed["payload"].clone())
            .with_client(client);

        Ok(event)
    }

    /// Parse event type string
    fn parse_event_type(s: &str) -> Result<EventType, EventError> {
        use super::source::{FirewallEventType, ServiceEventType, SystemEventType};

        let parts: Vec<&str> = s.split('.').collect();

        match parts.as_slice() {
            ["firewall", "block_ip"] => Ok(EventType::Firewall(FirewallEventType::BlockIp)),
            ["firewall", "unblock_ip"] => Ok(EventType::Firewall(FirewallEventType::UnblockIp)),
            ["firewall", "add_rule"] => Ok(EventType::Firewall(FirewallEventType::AddRule)),
            ["firewall", "remove_rule"] => Ok(EventType::Firewall(FirewallEventType::RemoveRule)),
            ["firewall", "flush_chain"] => Ok(EventType::Firewall(FirewallEventType::FlushChain)),

            ["service", "start"] => Ok(EventType::Service(ServiceEventType::Start)),
            ["service", "stop"] => Ok(EventType::Service(ServiceEventType::Stop)),
            ["service", "restart"] => Ok(EventType::Service(ServiceEventType::Restart)),
            ["service", "enable"] => Ok(EventType::Service(ServiceEventType::Enable)),
            ["service", "disable"] => Ok(EventType::Service(ServiceEventType::Disable)),

            ["system", "shutdown"] => Ok(EventType::System(SystemEventType::Shutdown)),
            ["system", "reload"] => Ok(EventType::System(SystemEventType::Reload)),
            ["system", "status"] => Ok(EventType::System(SystemEventType::Status)),
            ["system", "health_check"] => Ok(EventType::System(SystemEventType::HealthCheck)),

            _ => Ok(EventType::Custom(s.to_string())),
        }
    }
}

#[async_trait::async_trait]
impl EventSource for IpcEventSource {
    async fn next_event(&mut self) -> Option<Event> {
        // Try to accept a connection and process it
        tokio::select! {
            result = self.listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        // Spawn handler for this client
                        let event_tx = self.event_tx.clone();
                        let client_count = self.client_count.clone();
                        let rate_limiter = self.rate_limiter.clone();

                        tokio::spawn(async move {
                            Self::handle_client(stream, event_tx, client_count, rate_limiter).await;
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            event = self.event_rx.recv() => {
                return event;
            }
        }

        None
    }

    async fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        info!("IPC event source shutdown");
    }

    fn name(&self) -> &str {
        "ipc"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_parsing() {
        assert!(matches!(
            IpcEventSource::parse_event_type("firewall.block_ip"),
            Ok(EventType::Firewall(_))
        ));

        assert!(matches!(
            IpcEventSource::parse_event_type("service.start"),
            Ok(EventType::Service(_))
        ));

        assert!(matches!(
            IpcEventSource::parse_event_type("custom.foo"),
            Ok(EventType::Custom(_))
        ));
    }
}
