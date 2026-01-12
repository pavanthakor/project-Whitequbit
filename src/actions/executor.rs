//! Action Executor - Sandboxed action execution
//!
//! Executes actions in a forked, sandboxed process for isolation.

use std::time::Duration;

use tokio::time::timeout;
use tracing::instrument;

use super::action::{Action, ActionResult, ExecutionContext};
use super::ActionError;

/// Default action timeout
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum action timeout
const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// Executor for actions in sandboxed environment
pub struct ActionExecutor {
    /// Default execution context
    default_context: ExecutionContext,
}

impl ActionExecutor {
    /// Create a new action executor
    pub fn new() -> Self {
        Self {
            default_context: ExecutionContext::default(),
        }
    }

    /// Create an executor with custom default context
    pub fn with_context(context: ExecutionContext) -> Self {
        Self {
            default_context: context,
        }
    }

    /// Execute an action
    #[instrument(skip(self, action), fields(action_id = %action.id(), action_type = action.action_type()))]
    pub async fn execute(&self, action: &dyn Action) -> Result<ActionResult, ActionError> {
        let action_id = action.id();
        let timeout_duration = action
            .estimated_duration()
            .min(MAX_TIMEOUT)
            .max(DEFAULT_TIMEOUT);

        tracing::info!("Executing action with timeout {:?}", timeout_duration);

        // Execute with timeout
        let result = timeout(timeout_duration, self.execute_inner(action)).await;

        match result {
            Ok(inner_result) => inner_result,
            Err(_) => {
                tracing::error!("Action {:?} timed out", action_id);
                Err(ActionError::Timeout(timeout_duration))
            }
        }
    }

    /// Inner execution logic
    async fn execute_inner(&self, action: &dyn Action) -> Result<ActionResult, ActionError> {
        // In a production implementation, this would:
        // 1. Fork a child process
        // 2. Apply sandbox restrictions (seccomp, landlock)
        // 3. Execute the action in the child
        // 4. Collect the result via IPC
        // 5. Kill the child if it exceeds timeout

        // For now, we execute directly (not production-safe)
        tracing::debug!("Executing action directly (sandbox not implemented)");

        #[cfg(unix)]
        {
            self.execute_forked(action).await
        }

        #[cfg(not(unix))]
        {
            self.execute_direct(action).await
        }
    }

    /// Execute action directly (no sandbox)
    async fn execute_direct(&self, action: &dyn Action) -> Result<ActionResult, ActionError> {
        action.execute(&self.default_context)
    }

    /// Execute action in a forked process (Unix only)
    #[cfg(unix)]
    async fn execute_forked(&self, action: &dyn Action) -> Result<ActionResult, ActionError> {
        use std::io::{Read, Write};
        use std::os::unix::io::{FromRawFd, RawFd};

        // Create a pipe for IPC
        let (read_fd, write_fd) = nix::unistd::pipe()
            .map_err(|e| ActionError::Sandbox(format!("Failed to create pipe: {}", e)))?;

        // Fork the process to execute action in isolation
        // SAFETY: fork() is safe when called in a single-threaded context before spawning
        // tokio tasks, or when we properly handle the child process not using async runtime
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Child) => {
                // Child process - close read end of pipe
                // SAFETY: read_fd is a valid fd from pipe() above
                drop(unsafe { std::fs::File::from_raw_fd(read_fd) });

                // Apply additional sandbox restrictions here
                // self.apply_child_sandbox();

                // Execute the action
                let result = action.execute(&self.default_context);

                // Serialize and send result
                let result_bytes = match &result {
                    Ok(r) => serde_json::to_vec(r).unwrap_or_default(),
                    Err(e) => format!("ERROR:{}", e).into_bytes(),
                };

                // SAFETY: write_fd is a valid fd from pipe(), we own it in child process
                let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
                let _ = write_file.write_all(&result_bytes);
                drop(write_file);

                // Exit child
                std::process::exit(if result.is_ok() { 0 } else { 1 });
            }
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                // Parent process - close write end of pipe
                // SAFETY: write_fd is a valid fd from pipe() above
                drop(unsafe { std::fs::File::from_raw_fd(write_fd) });

                // Read result from child
                // SAFETY: read_fd is a valid fd from pipe() above
                let mut read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
                let mut result_bytes = Vec::new();
                read_file
                    .read_to_end(&mut result_bytes)
                    .map_err(|e| ActionError::Sandbox(format!("Failed to read result: {}", e)))?;

                // Wait for child
                let status = nix::sys::wait::waitpid(child, None)
                    .map_err(|e| ActionError::Sandbox(format!("Failed to wait for child: {}", e)))?;

                // Parse result
                let result_str = String::from_utf8_lossy(&result_bytes);
                if result_str.starts_with("ERROR:") {
                    return Err(ActionError::Execution(
                        result_str.strip_prefix("ERROR:").unwrap_or(&result_str).to_string(),
                    ));
                }

                serde_json::from_slice(&result_bytes)
                    .map_err(|e| ActionError::Serialization(format!("Failed to parse result: {}", e)))
            }
            Err(e) => Err(ActionError::Sandbox(format!("Fork failed: {}", e))),
        }
    }

    /// Execute a compensation action (rollback)
    #[instrument(skip(self, action), fields(action_id = %action.id()))]
    pub async fn execute_rollback(&self, action: &dyn Action) -> Result<ActionResult, ActionError> {
        tracing::info!("Executing rollback action");
        self.execute(action).await
    }
}

impl Default for ActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    // Tests would go here
}