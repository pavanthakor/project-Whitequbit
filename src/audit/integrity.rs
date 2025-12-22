//! Integrity Verifier - Hash chain verification
//!
//! Verifies the integrity of the audit log by checking hash chains.

use std::io::{BufRead, BufReader};
use std::path::Path;

use tracing::{debug, error, info, warn};

use super::logger::AuditEntry;
use super::AuditError;

/// Result of an integrity verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether the verification passed
    pub valid: bool,
    /// Total entries checked
    pub entries_checked: u64,
    /// First invalid entry (if any)
    pub first_invalid: Option<u64>,
    /// Description of the issue (if any)
    pub issue: Option<String>,
}

impl VerificationResult {
    /// Create a passing result
    pub fn pass(entries_checked: u64) -> Self {
        Self {
            valid: true,
            entries_checked,
            first_invalid: None,
            issue: None,
        }
    }

    /// Create a failing result
    pub fn fail(entries_checked: u64, first_invalid: u64, issue: impl Into<String>) -> Self {
        Self {
            valid: false,
            entries_checked,
            first_invalid: Some(first_invalid),
            issue: Some(issue.into()),
        }
    }
}

/// Verifier for audit log integrity
pub struct IntegrityVerifier;

impl IntegrityVerifier {
    /// Verify the integrity of an audit log file
    pub fn verify_file(path: impl AsRef<Path>) -> Result<VerificationResult, AuditError> {
        let path = path.as_ref();
        info!("Verifying integrity of {}", path.display());

        if !path.exists() {
            return Ok(VerificationResult::pass(0));
        }

        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);

        let mut entries_checked = 0u64;
        let mut expected_sequence = 1u64;
        let mut expected_previous_hash = String::new();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;

            entries_checked += 1;

            // Check sequence number
            if entry.sequence != expected_sequence {
                error!(
                    "Sequence mismatch at entry {}: expected {}, got {}",
                    entries_checked, expected_sequence, entry.sequence
                );
                return Ok(VerificationResult::fail(
                    entries_checked,
                    entry.sequence,
                    format!(
                        "Sequence mismatch: expected {}, got {}",
                        expected_sequence, entry.sequence
                    ),
                ));
            }

            // Check previous hash chain
            if entry.previous_hash != expected_previous_hash {
                error!(
                    "Hash chain broken at entry {}: expected {}, got {}",
                    entry.sequence, expected_previous_hash, entry.previous_hash
                );
                return Ok(VerificationResult::fail(
                    entries_checked,
                    entry.sequence,
                    "Hash chain broken",
                ));
            }

            // Verify entry's own hash
            if !entry.verify() {
                error!("Entry {} has invalid hash", entry.sequence);
                return Ok(VerificationResult::fail(
                    entries_checked,
                    entry.sequence,
                    "Entry hash mismatch",
                ));
            }

            // Update expectations for next entry
            expected_sequence += 1;
            expected_previous_hash = entry.hash.clone();

            debug!("Entry {} verified", entry.sequence);
        }

        info!(
            "Integrity verification passed: {} entries checked",
            entries_checked
        );
        Ok(VerificationResult::pass(entries_checked))
    }

    /// Verify and report any gaps in the log
    pub fn find_gaps(path: impl AsRef<Path>) -> Result<Vec<(u64, u64)>, AuditError> {
        let path = path.as_ref();

        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);

        let mut gaps = Vec::new();
        let mut expected_sequence = 1u64;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;

            if entry.sequence > expected_sequence {
                gaps.push((expected_sequence, entry.sequence - 1));
                warn!(
                    "Gap detected: entries {} to {} missing",
                    expected_sequence,
                    entry.sequence - 1
                );
            }

            expected_sequence = entry.sequence + 1;
        }

        Ok(gaps)
    }

    /// Get statistics about the audit log
    pub fn get_stats(path: impl AsRef<Path>) -> Result<AuditStats, AuditError> {
        let path = path.as_ref();

        if !path.exists() {
            return Ok(AuditStats::default());
        }

        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);

        let mut stats = AuditStats::default();

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;

            stats.total_entries += 1;

            if stats.first_entry.is_none() {
                stats.first_entry = Some(entry.timestamp);
            }
            stats.last_entry = Some(entry.timestamp);
            stats.last_sequence = entry.sequence;
        }

        Ok(stats)
    }
}

/// Statistics about an audit log
#[derive(Debug, Default)]
pub struct AuditStats {
    /// Total number of entries
    pub total_entries: u64,
    /// Timestamp of first entry
    pub first_entry: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of last entry
    pub last_entry: Option<chrono::DateTime<chrono::Utc>>,
    /// Last sequence number
    pub last_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_verify_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let result = IntegrityVerifier::verify_file(&path).unwrap();
        assert!(result.valid);
        assert_eq!(result.entries_checked, 0);
    }
}
