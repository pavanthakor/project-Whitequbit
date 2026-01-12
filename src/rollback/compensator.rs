//! Compensator - Rollback execution engine
//!
//! Executes compensation actions in the correct order to undo changes.

use std::time::Duration;



use super::journal::{JournalEntryId, UncommittedEntry};

/// Result of a compensation attempt
#[derive(Debug)]
pub struct CompensationResult {
    /// Entry ID that was compensated
    pub entry_id: JournalEntryId,
    /// Whether compensation succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl CompensationResult {
    /// Create a successful result
    pub fn success(entry_id: JournalEntryId) -> Self {
        Self {
            entry_id,
            success: true,
            error: None,
        }
    }

    /// Create a failed result
    pub fn failure(entry_id: JournalEntryId, error: impl Into<String>) -> Self {
        Self {
            entry_id,
            success: false,
            error: Some(error.into()),
        }
    }
}

/// Handler function type for executing compensation based on action type
pub type CompensationHandler = Box<
    dyn Fn(&str, &serde_json::Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

/// Executes compensation actions for rollback
pub struct Compensator {
    /// Maximum retries for failed compensations
    max_retries: usize,
    /// Delay between retries
    retry_delay: Duration,
    /// Handlers for different action types
    handlers: std::collections::HashMap<String, CompensationHandler>,
}

impl Compensator {
    /// Create a new compensator
    pub fn new() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            handlers: std::collections::HashMap::new(),
        }
    }

    /// Set maximum retries
    pub fn with_max_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set retry delay
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    /// Register a compensation handler for an action type
    pub fn register_handler(
        mut self,
        action_type: impl Into<String>,
        handler: CompensationHandler,
    ) -> Self {
        self.handlers.insert(action_type.into(), handler);
        self
    }

    /// Execute a single compensation action with retries
    pub async fn compensate(&self, entry: &UncommittedEntry) -> CompensationResult {
        tracing::info!(
            "Compensating action {} (entry {})",
            entry.action_id, entry.id
        );

        let handler = match self.handlers.get(&entry.action_type) {
            Some(h) => h,
            None => {
                tracing::warn!(
                    "No handler registered for action type: {}",
                    entry.action_type
                );
                return CompensationResult::failure(
                    entry.id,
                    format!("No handler for action type: {}", entry.action_type),
                );
            }
        };

        let mut last_error = String::new();

        for attempt in 1..=self.max_retries {
            tracing::debug!(
                "Compensation attempt {}/{} for entry {}",
                attempt, self.max_retries, entry.id
            );

            match handler(&entry.action_type, &entry.compensation_data).await {
                Ok(()) => {
                    tracing::info!("Compensation succeeded for entry {}", entry.id);
                    return CompensationResult::success(entry.id);
                }
                Err(e) => {
                    last_error = e;
                    tracing::warn!(
                        "Compensation attempt {} failed for entry {}: {}",
                        attempt, entry.id, last_error
                    );

                    if attempt < self.max_retries {
                        tokio::time::sleep(self.retry_delay).await;
                    }
                }
            }
        }

        tracing::error!(
            "Compensation failed for entry {} after {} retries: {}",
            entry.id, self.max_retries, last_error
        );

        CompensationResult::failure(entry.id, last_error)
    }

    /// Compensate multiple entries in LIFO order
    pub async fn compensate_all(
        &self,
        mut entries: Vec<UncommittedEntry>,
    ) -> Vec<CompensationResult> {
        // Sort by entry ID descending (LIFO order)
        entries.sort_by(|a, b| b.id.as_u64().cmp(&a.id.as_u64()));

        tracing::info!(
            "Compensating {} entries in LIFO order",
            entries.len()
        );

        let mut results = Vec::new();

        for entry in &entries {
            let result = self.compensate(entry).await;
            let success = result.success;
            results.push(result);

            if !success {
                // Continue trying other compensations, but log the failure
                tracing::warn!(
                    "Compensation failed for entry {}, continuing with others",
                    entry.id
                );
            }
        }

        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = results.len() - succeeded;

        tracing::info!(
            "Compensation complete: {} succeeded, {} failed",
            succeeded, failed
        );

        results
    }

    /// Check if all compensations succeeded
    pub fn all_succeeded(results: &[CompensationResult]) -> bool {
        results.iter().all(|r| r.success)
    }

    /// Get failed compensations
    pub fn get_failed(results: &[CompensationResult]) -> Vec<&CompensationResult> {
        results.iter().filter(|r| !r.success).collect()
    }
}

impl Default for Compensator {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create compensation handlers easily
pub mod handlers {
    use super::*;

    /// Create a no-op handler (for testing or actions that don't need compensation)
    #[allow(dead_code)]
    pub fn noop() -> CompensationHandler {
        Box::new(|_action_type, _data| {
            Box::pin(async { Ok(()) })
        })
    }

    /// Create a handler that always fails (for testing)
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn always_fail(message: &'static str) -> CompensationHandler {
        Box::new(move |_action_type, _data| {
            Box::pin(async move { Err(message.to_string()) })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionId;

    #[tokio::test]
    async fn test_compensator_success() {
        let compensator = Compensator::new()
            .register_handler("test_action", handlers::noop());

        let entry = UncommittedEntry {
            id: super::super::journal::JournalEntryId::new(1),
            action_id: ActionId::new(),
            action_type: "test_action".to_string(),
            compensation_data: serde_json::json!({}),
        };

        let result = compensator.compensate(&entry).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_compensator_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();

        let handler: CompensationHandler = Box::new(move |_action_type, _data| {
            let attempts = attempts_clone.clone();
            Box::pin(async move {
                let count = attempts.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    Err("Temporary failure".to_string())
                } else {
                    Ok(())
                }
            })
        });

        let compensator = Compensator::new()
            .with_retry_delay(Duration::from_millis(10))
            .register_handler("test_action", handler);

        let entry = UncommittedEntry {
            id: super::super::journal::JournalEntryId::new(1),
            action_id: ActionId::new(),
            action_type: "test_action".to_string(),
            compensation_data: serde_json::json!({}),
        };

        let result = compensator.compensate(&entry).await;
        assert!(result.success);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }
}
