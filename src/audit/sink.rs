//! Audit Sinks - Destinations for audit log entries
//!
//! Supports file, syslog, and remote sinks using an enum-based approach
//! to avoid dyn-compatibility issues with async traits.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use tokio::sync::Mutex;

use super::logger::AuditEntry;
use super::AuditError;

/// File-based audit sink
pub struct FileSink {
    /// Path to the audit log file
    path: PathBuf,
    /// File handle (protected by mutex for async safety)
    file: Mutex<std::fs::File>,
}

impl FileSink {
    /// Create a new file sink
    pub fn new(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Open file in append mode
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    /// Write an entry to the file
    pub async fn write(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let line = serde_json::to_string(entry)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        let mut file = self.file.lock().await;
        writeln!(file, "{}", line)?;

        // Ensure durability
        file.sync_all()?;

        tracing::debug!("Wrote audit entry {} to {}", entry.sequence, self.path.display());
        Ok(())
    }

    /// Flush pending writes
    pub async fn flush(&self) -> Result<(), AuditError> {
        let file = self.file.lock().await;
        file.sync_all()?;
        Ok(())
    }

    /// Get the current chain state (next sequence, last hash)
    pub fn get_chain_state(&self) -> Result<(u64, String), AuditError> {
        if !self.path.exists() {
            return Ok((1, String::new()));
        }

        let file = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(file);

        let mut last_sequence = 0u64;
        let mut last_hash = String::new();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;

            last_sequence = entry.sequence;
            last_hash = entry.hash;
        }

        Ok((last_sequence + 1, last_hash))
    }
}

/// Syslog-based audit sink (Unix only)
#[cfg(unix)]
pub struct SyslogSink {
    /// Syslog facility
    facility: String,
    /// Application name
    app_name: String,
}

#[cfg(unix)]
impl SyslogSink {
    /// Create a new syslog sink
    pub fn new(facility: impl Into<String>, app_name: impl Into<String>) -> Result<Self, AuditError> {
        Ok(Self {
            facility: facility.into(),
            app_name: app_name.into(),
        })
    }

    /// Write an entry to syslog
    pub async fn write(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let message = serde_json::to_string(entry)
            .map_err(|e| AuditError::Serialization(e.to_string()))?;

        // Use logger command to write to syslog
        let output = std::process::Command::new("logger")
            .args([
                "-p",
                &format!("{}.info", self.facility),
                "-t",
                &self.app_name,
                &message,
            ])
            .output()
            .map_err(|e| AuditError::Sink(format!("Failed to write to syslog: {}", e)))?;

        if !output.status.success() {
            return Err(AuditError::Sink(format!(
                "Syslog write failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Flush (no-op for syslog)
    pub async fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }

    /// Get the current chain state
    pub fn get_chain_state(&self) -> Result<(u64, String), AuditError> {
        // Syslog doesn't maintain chain state
        Ok((1, String::new()))
    }
}

/// Syslog-based audit sink (stub for non-Unix platforms)
#[cfg(not(unix))]
pub struct SyslogSink;

#[cfg(not(unix))]
impl SyslogSink {
    /// Create a new syslog sink (not supported on this platform)
    pub fn new(_facility: impl Into<String>, _app_name: impl Into<String>) -> Result<Self, AuditError> {
        Err(AuditError::Sink("Syslog not supported on this platform".to_string()))
    }

    /// Write an entry to syslog (not supported on this platform)
    pub async fn write(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
        Err(AuditError::Sink("Syslog not supported on this platform".to_string()))
    }

    /// Flush pending writes (no-op)
    pub async fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }

    /// Get the current chain state
    pub fn get_chain_state(&self) -> Result<(u64, String), AuditError> {
        Ok((1, String::new()))
    }
}

/// Enum-based sink that supports multiple sink types
/// This approach avoids dyn-compatibility issues with async traits
pub enum AuditSinkType {
    /// File-based sink
    File(FileSink),
    /// Syslog-based sink
    Syslog(SyslogSink),
}

impl AuditSinkType {
    /// Create a file sink
    pub fn file(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Ok(Self::File(FileSink::new(path)?))
    }

    /// Create a syslog sink
    #[cfg(unix)]
    pub fn syslog(facility: impl Into<String>, app_name: impl Into<String>) -> Result<Self, AuditError> {
        Ok(Self::Syslog(SyslogSink::new(facility, app_name)?))
    }

    /// Write an entry to the sink
    pub async fn write(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        match self {
            Self::File(sink) => sink.write(entry).await,
            Self::Syslog(sink) => sink.write(entry).await,
        }
    }

    /// Flush the sink
    pub async fn flush(&self) -> Result<(), AuditError> {
        match self {
            Self::File(sink) => sink.flush().await,
            Self::Syslog(sink) => sink.flush().await,
        }
    }

    /// Get the current chain state
    pub fn get_chain_state(&self) -> Result<(u64, String), AuditError> {
        match self {
            Self::File(sink) => sink.get_chain_state(),
            Self::Syslog(sink) => sink.get_chain_state(),
        }
    }
}

/// Multi-sink that writes to multiple destinations
pub struct MultiSink {
    sinks: Vec<AuditSinkType>,
}

impl MultiSink {
    /// Create a new multi-sink
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    /// Add a sink
    pub fn add_sink(mut self, sink: AuditSinkType) -> Self {
        self.sinks.push(sink);
        self
    }

    /// Write an entry to all sinks
    pub async fn write(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        for sink in &self.sinks {
            sink.write(entry).await?;
        }
        Ok(())
    }

    /// Flush all sinks
    pub async fn flush(&self) -> Result<(), AuditError> {
        for sink in &self.sinks {
            sink.flush().await?;
        }
        Ok(())
    }

    /// Get the current chain state from the first sink
    pub fn get_chain_state(&self) -> Result<(u64, String), AuditError> {
        self.sinks
            .first()
            .map(|s| s.get_chain_state())
            .unwrap_or(Ok((1, String::new())))
    }
}

impl Default for MultiSink {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_file_sink() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let sink = FileSink::new(&path).unwrap();

        let entry = AuditEntry {
            sequence: 1,
            timestamp: chrono::Utc::now(),
            event_type: super::super::logger::AuditEventType::AgentStartup,
            actor: None,
            target: None,
            details: serde_json::Value::Null,
            previous_hash: String::new(),
            hash: "test".to_string(),
        };

        sink.write(&entry).await.unwrap();

        let (next_seq, _) = sink.get_chain_state().unwrap();
        assert_eq!(next_seq, 2);
    }
}
