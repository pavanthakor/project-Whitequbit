//! Service Actions - System service management
//!
//! Supports starting, stopping, enabling, and disabling system services.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::action::{Action, ActionId, ActionResult, ExecutionContext, ValidationError};
use super::privileged_executor::{Capability, CapabilitySet};
use super::ActionError;

/// Service operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceOperation {
    /// Start a service
    Start,
    /// Stop a service
    Stop,
    /// Restart a service
    Restart,
    /// Enable a service (start on boot)
    Enable,
    /// Disable a service (don't start on boot)
    Disable,
    /// Reload service configuration
    Reload,
    /// Mask a service (prevent starting)
    Mask,
    /// Unmask a service
    Unmask,
}

impl ServiceOperation {
    /// Get the inverse operation for rollback
    pub fn inverse(&self) -> Option<Self> {
        match self {
            ServiceOperation::Start => Some(ServiceOperation::Stop),
            ServiceOperation::Stop => Some(ServiceOperation::Start),
            ServiceOperation::Enable => Some(ServiceOperation::Disable),
            ServiceOperation::Disable => Some(ServiceOperation::Enable),
            ServiceOperation::Mask => Some(ServiceOperation::Unmask),
            ServiceOperation::Unmask => Some(ServiceOperation::Mask),
            // Restart and Reload don't have simple inverses
            ServiceOperation::Restart => None,
            ServiceOperation::Reload => None,
        }
    }
}

/// Service state before action (for rollback)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceState {
    /// Whether the service was running
    pub running: bool,
    /// Whether the service was enabled
    pub enabled: bool,
    /// Whether the service was masked
    pub masked: bool,
}

/// Service action - manages system services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAction {
    /// Unique action ID
    id: ActionId,
    /// Service name
    pub service_name: String,
    /// Operation to perform
    pub operation: ServiceOperation,
    /// Captured state before execution (for accurate rollback)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_state: Option<ServiceState>,
}

impl ServiceAction {
    /// Create a new service action
    pub fn new(service_name: impl Into<String>, operation: ServiceOperation) -> Self {
        Self {
            id: ActionId::new(),
            service_name: service_name.into(),
            operation,
            previous_state: None,
        }
    }

    /// Create with specific ID (for deserialization)
    pub fn with_id(
        id: ActionId,
        service_name: impl Into<String>,
        operation: ServiceOperation,
    ) -> Self {
        Self {
            id,
            service_name: service_name.into(),
            operation,
            previous_state: None,
        }
    }

    /// Capture current service state
    #[allow(dead_code)]
    fn capture_state(&self) -> Result<ServiceState, ActionError> {
        #[cfg(unix)]
        {
            let is_active = self.run_systemctl(&["is-active", "--quiet"]).is_ok();
            let is_enabled = self.run_systemctl(&["is-enabled", "--quiet"]).is_ok();

            // Check if masked
            let status_output = std::process::Command::new("systemctl")
                .args(["show", "-p", "LoadState", &self.service_name])
                .output()
                .map_err(|e| ActionError::Execution(format!("Failed to check service state: {}", e)))?;

            let is_masked = String::from_utf8_lossy(&status_output.stdout)
                .contains("masked");

            Ok(ServiceState {
                running: is_active,
                enabled: is_enabled,
                masked: is_masked,
            })
        }

        #[cfg(not(unix))]
        {
            Err(ActionError::Execution(
                "Service actions only supported on Unix".to_string(),
            ))
        }
    }

    /// Run a systemctl command
    #[cfg(unix)]
    fn run_systemctl(&self, args: &[&str]) -> Result<std::process::Output, ActionError> {
        let mut cmd_args: Vec<&str> = args.to_vec();
        cmd_args.push(&self.service_name);

        let output = std::process::Command::new("systemctl")
            .args(&cmd_args)
            .output()
            .map_err(|e| ActionError::Execution(format!("Failed to execute systemctl: {}", e)))?;

        if output.status.success() {
            Ok(output)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(ActionError::Execution(format!(
                "systemctl {} failed: {}",
                args.join(" "),
                stderr
            )))
        }
    }

    /// Validate service name
    fn validate_service_name(name: &str) -> Result<(), ValidationError> {
        // Service names should be alphanumeric with dashes, underscores, and @ for templated units
        if name.is_empty() {
            return Err(ValidationError::MissingField("service_name".to_string()));
        }

        let valid_chars = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '@' || c == '.');

        if !valid_chars {
            return Err(ValidationError::InvalidValue {
                field: "service_name".to_string(),
                reason: "Service name contains invalid characters".to_string(),
            });
        }

        // Prevent path traversal
        if name.contains("..") || name.contains('/') {
            return Err(ValidationError::InvalidValue {
                field: "service_name".to_string(),
                reason: "Service name cannot contain path separators".to_string(),
            });
        }

        Ok(())
    }
}

impl Action for ServiceAction {
    fn id(&self) -> ActionId {
        self.id
    }

    fn action_type(&self) -> &'static str {
        "service"
    }

    fn validate(&self) -> Result<(), ValidationError> {
        Self::validate_service_name(&self.service_name)?;

        // Check for dangerous services
        const PROTECTED_SERVICES: &[&str] = &[
            "systemd",
            "init",
            "dbus",
            "udev",
            "journal",
        ];

        let base_name = self.service_name
            .split('@')
            .next()
            .unwrap_or(&self.service_name)
            .trim_end_matches(".service");

        for protected in PROTECTED_SERVICES {
            if base_name.contains(protected) {
                return Err(ValidationError::PolicyViolation(format!(
                    "Cannot modify protected service: {}",
                    self.service_name
                )));
            }
        }

        Ok(())
    }

    fn execute(&self, ctx: &ExecutionContext) -> Result<ActionResult, ActionError> {
        info!(
            "Executing service action: {:?} on {}",
            self.operation, self.service_name
        );

        if ctx.dry_run {
            return Ok(ActionResult::no_change(format!(
                "Dry run: would {:?} service {}",
                self.operation, self.service_name
            )));
        }

        #[cfg(unix)]
        {
            // Capture state before modification
            let _previous_state = self.capture_state()?;

            let operation_str = match self.operation {
                ServiceOperation::Start => "start",
                ServiceOperation::Stop => "stop",
                ServiceOperation::Restart => "restart",
                ServiceOperation::Enable => "enable",
                ServiceOperation::Disable => "disable",
                ServiceOperation::Reload => "reload",
                ServiceOperation::Mask => "mask",
                ServiceOperation::Unmask => "unmask",
            };

            self.run_systemctl(&[operation_str])?;

            Ok(ActionResult::changed(format!(
                "Service {} {}ed",
                self.service_name, operation_str
            )))
        }

        #[cfg(not(unix))]
        {
            Err(ActionError::Execution(
                "Service actions only supported on Unix".to_string(),
            ))
        }
    }

    fn compensation(&self) -> Box<dyn Action> {
        // If we have previous state, use it for accurate rollback
        if let Some(ref state) = self.previous_state {
            // Create actions to restore the exact previous state
            let restore_op = match self.operation {
                ServiceOperation::Start if !state.running => ServiceOperation::Stop,
                ServiceOperation::Stop if state.running => ServiceOperation::Start,
                ServiceOperation::Enable if !state.enabled => ServiceOperation::Disable,
                ServiceOperation::Disable if state.enabled => ServiceOperation::Enable,
                ServiceOperation::Mask if !state.masked => ServiceOperation::Unmask,
                ServiceOperation::Unmask if state.masked => ServiceOperation::Mask,
                _ => {
                    // No change needed or not reversible
                    return Box::new(NoOpAction::new(format!(
                        "No rollback needed for {:?} on {}",
                        self.operation, self.service_name
                    )));
                }
            };

            return Box::new(ServiceAction::with_id(
                ActionId::new(),
                &self.service_name,
                restore_op,
            ));
        }

        // Fallback: use simple inverse operation
        if let Some(inverse) = self.operation.inverse() {
            Box::new(ServiceAction::with_id(
                ActionId::new(),
                &self.service_name,
                inverse,
            ))
        } else {
            Box::new(NoOpAction::new(format!(
                "No inverse for {:?} on {}",
                self.operation, self.service_name
            )))
        }
    }

    fn serialize(&self) -> Result<Vec<u8>, ActionError> {
        serde_json::to_vec(self).map_err(|e| ActionError::Serialization(e.to_string()))
    }

    fn description(&self) -> String {
        format!("{:?} service {}", self.operation, self.service_name)
    }

    fn estimated_duration(&self) -> Duration {
        match self.operation {
            ServiceOperation::Start | ServiceOperation::Restart => Duration::from_secs(10),
            ServiceOperation::Stop => Duration::from_secs(5),
            _ => Duration::from_secs(2),
        }
    }

    fn required_capabilities(&self) -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        // Service operations that affect process state need CAP_KILL
        match self.operation {
            ServiceOperation::Start
            | ServiceOperation::Stop
            | ServiceOperation::Restart
            | ServiceOperation::Reload => {
                caps.insert(Capability::Kill);
            }
            // Enable/disable/mask only modify symlinks, no special cap needed
            // (but we're running as non-root with access to systemd socket)
            _ => {}
        }
        caps
    }
}

/// No-op action for cases where rollback isn't needed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoOpAction {
    id: ActionId,
    message: String,
}

impl NoOpAction {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            id: ActionId::new(),
            message: message.into(),
        }
    }
}

impl Action for NoOpAction {
    fn id(&self) -> ActionId {
        self.id
    }

    fn action_type(&self) -> &'static str {
        "noop"
    }

    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }

    fn execute(&self, _ctx: &ExecutionContext) -> Result<ActionResult, ActionError> {
        debug!("NoOp action: {}", self.message);
        Ok(ActionResult::no_change(&self.message))
    }

    fn compensation(&self) -> Box<dyn Action> {
        Box::new(self.clone())
    }

    fn serialize(&self) -> Result<Vec<u8>, ActionError> {
        serde_json::to_vec(self).map_err(|e| ActionError::Serialization(e.to_string()))
    }

    fn description(&self) -> String {
        format!("NoOp: {}", self.message)
    }

    fn requires_privilege(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_name_validation() {
        assert!(ServiceAction::validate_service_name("nginx").is_ok());
        assert!(ServiceAction::validate_service_name("ssh.service").is_ok());
        assert!(ServiceAction::validate_service_name("user@1000").is_ok());

        assert!(ServiceAction::validate_service_name("").is_err());
        assert!(ServiceAction::validate_service_name("../etc/passwd").is_err());
        assert!(ServiceAction::validate_service_name("service;rm -rf /").is_err());
    }

    #[test]
    fn test_protected_services() {
        let action = ServiceAction::new("systemd-journald", ServiceOperation::Stop);
        assert!(action.validate().is_err());
    }

    #[test]
    fn test_inverse_operations() {
        assert_eq!(
            ServiceOperation::Start.inverse(),
            Some(ServiceOperation::Stop)
        );
        assert_eq!(
            ServiceOperation::Enable.inverse(),
            Some(ServiceOperation::Disable)
        );
        assert_eq!(ServiceOperation::Restart.inverse(), None);
    }
}
