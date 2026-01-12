//! Policy Engine - Authorization rules
//!
//! Defines and enforces policies for action authorization.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};


use crate::actions::Action;

use super::auth::ClientAuth;
use super::SecurityError;

/// Policy decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// A policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,
    /// Action types this rule applies to (empty = all)
    pub action_types: Vec<String>,
    /// Required roles (any of these)
    pub required_roles: Vec<String>,
    /// Required groups (any of these)
    pub required_groups: Vec<String>,
    /// Minimum UID (inclusive)
    pub min_uid: Option<u32>,
    /// Maximum UID (inclusive)
    pub max_uid: Option<u32>,
    /// Whether to allow or deny
    pub decision: PolicyDecision,
    /// Priority (higher = evaluated first)
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    Allow,
    Deny,
}

impl PolicyRule {
    /// Create a new allow rule
    pub fn allow(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            action_types: Vec::new(),
            required_roles: Vec::new(),
            required_groups: Vec::new(),
            min_uid: None,
            max_uid: None,
            decision: PolicyDecision::Allow,
            priority: 0,
        }
    }

    /// Create a new deny rule
    pub fn deny(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            action_types: Vec::new(),
            required_roles: Vec::new(),
            required_groups: Vec::new(),
            min_uid: None,
            max_uid: None,
            decision: PolicyDecision::Deny,
            priority: 0,
        }
    }

    /// Require specific action types
    pub fn for_actions(mut self, types: Vec<String>) -> Self {
        self.action_types = types;
        self
    }

    /// Require specific roles
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.required_roles = roles;
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Check if this rule matches the action and client
    fn matches(&self, action: &dyn Action, client: &ClientAuth) -> bool {
        // Check action type
        if !self.action_types.is_empty() {
            if !self.action_types.contains(&action.action_type().to_string()) {
                return false;
            }
        }

        // Check roles
        if !self.required_roles.is_empty() {
            let has_role = self.required_roles.iter().any(|r| client.has_role(r));
            if !has_role {
                return false;
            }
        }

        // Check groups
        if !self.required_groups.is_empty() {
            let in_group = self.required_groups.iter().any(|g| client.in_group(g));
            if !in_group {
                return false;
            }
        }

        // Check UID range
        if let Some(uid) = client.uid {
            if let Some(min) = self.min_uid {
                if uid < min {
                    return false;
                }
            }
            if let Some(max) = self.max_uid {
                if uid > max {
                    return false;
                }
            }
        }

        true
    }
}

/// A policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy name
    pub name: String,
    /// Policy rules
    pub rules: Vec<PolicyRule>,
    /// Default decision when no rules match
    pub default_decision: PolicyDecision,
}

impl Policy {
    /// Create a new policy with deny-by-default
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rules: Vec::new(),
            default_decision: PolicyDecision::Deny,
        }
    }

    /// Add a rule
    pub fn add_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Set default decision
    pub fn with_default(mut self, decision: PolicyDecision) -> Self {
        self.default_decision = decision;
        self
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new("default")
            // Allow admins to do anything
            .add_rule(
                PolicyRule::allow("admin_all")
                    .with_roles(vec!["admin".to_string()])
                    .with_priority(100),
            )
            // Allow operators to manage services
            .add_rule(
                PolicyRule::allow("operator_services")
                    .with_roles(vec!["operator".to_string()])
                    .for_actions(vec!["service".to_string()])
                    .with_priority(50),
            )
            // Allow operators to manage firewall
            .add_rule(
                PolicyRule::allow("operator_firewall")
                    .with_roles(vec!["operator".to_string()])
                    .for_actions(vec!["firewall".to_string()])
                    .with_priority(50),
            )
            // Default: deny
            .with_default(PolicyDecision::Deny)
    }
}

/// Policy engine for evaluating authorization
pub struct PolicyEngine {
    /// Active policy
    policy: Policy,
    /// Cached decisions (action_type + client_id -> decision)
    cache: HashMap<String, Decision>,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            cache: HashMap::new(),
        }
    }

    /// Create with default policy
    pub fn with_default_policy() -> Self {
        Self::new(Policy::default())
    }

    /// Check if an action is authorized for a client
    pub fn authorize(
        &self,
        action: &dyn Action,
        client: &ClientAuth,
    ) -> Result<(), SecurityError> {
        let decision = self.evaluate(action, client);

        match decision {
            Decision::Allow => {
                tracing::debug!(
                    "Authorized action {} for client {}",
                    action.action_type(),
                    client.client_id
                );
                Ok(())
            }
            Decision::Deny => {
                tracing::warn!(
                    "Denied action {} for client {}",
                    action.action_type(),
                    client.client_id
                );
                Err(SecurityError::Authorization(format!(
                    "Action {} not allowed for client {}",
                    action.action_type(),
                    client.client_id
                )))
            }
        }
    }

    /// Evaluate policy for an action
    fn evaluate(&self, action: &dyn Action, client: &ClientAuth) -> Decision {
        // Sort rules by priority (descending)
        let mut rules: Vec<_> = self.policy.rules.iter().collect();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Find first matching rule
        for rule in rules {
            if rule.matches(action, client) {
                tracing::debug!(
                    "Rule '{}' matched for action {} client {}",
                    rule.name,
                    action.action_type(),
                    client.client_id
                );

                return match rule.decision {
                    PolicyDecision::Allow => Decision::Allow,
                    PolicyDecision::Deny => Decision::Deny,
                };
            }
        }

        // No rule matched, use default
        tracing::debug!(
            "No rule matched, using default decision for action {}",
            action.action_type()
        );

        match self.policy.default_decision {
            PolicyDecision::Allow => Decision::Allow,
            PolicyDecision::Deny => Decision::Deny,
        }
    }

    /// Reload policy
    pub fn reload(&mut self, policy: Policy) {
        tracing::info!("Reloading policy: {}", policy.name);
        self.policy = policy;
        self.cache.clear();
    }

    /// Get the current policy name
    pub fn policy_name(&self) -> &str {
        &self.policy.name
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::with_default_policy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{ActionId, ActionResult, ValidationError};
    use crate::security::auth::AuthMethod;
    use chrono::Utc;

    // Mock action for testing
    #[derive(Debug)]
    struct MockAction {
        action_type: String,
    }

    impl Action for MockAction {
        fn id(&self) -> ActionId {
            ActionId::new()
        }

        fn action_type(&self) -> &'static str {
            // This is a bit of a hack for testing
            Box::leak(self.action_type.clone().into_boxed_str())
        }

        fn validate(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn execute(
            &self,
            _ctx: &crate::actions::action::ExecutionContext,
        ) -> Result<ActionResult, crate::actions::ActionError> {
            Ok(ActionResult::no_change("mock"))
        }

        fn compensation(&self) -> Box<dyn Action> {
            Box::new(MockAction {
                action_type: self.action_type.clone(),
            })
        }

        fn serialize(&self) -> Result<Vec<u8>, crate::actions::ActionError> {
            Ok(Vec::new())
        }

        fn description(&self) -> String {
            "mock action".to_string()
        }
    }

    fn make_admin_client() -> ClientAuth {
        ClientAuth {
            client_id: "admin-client".to_string(),
            method: AuthMethod::PeerCredentials,
            uid: Some(0),
            gid: Some(0),
            groups: Vec::new(),
            roles: vec!["admin".to_string()],
            authenticated_at: Utc::now(),
            expires_at: None,
        }
    }

    fn make_operator_client() -> ClientAuth {
        ClientAuth {
            client_id: "operator-client".to_string(),
            method: AuthMethod::PeerCredentials,
            uid: Some(1000),
            gid: Some(1000),
            groups: Vec::new(),
            roles: vec!["operator".to_string()],
            authenticated_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn test_admin_allowed() {
        let engine = PolicyEngine::with_default_policy();
        let client = make_admin_client();
        let action = MockAction {
            action_type: "firewall".to_string(),
        };

        assert!(engine.authorize(&action, &client).is_ok());
    }

    #[test]
    fn test_operator_allowed_for_service() {
        let engine = PolicyEngine::with_default_policy();
        let client = make_operator_client();
        let action = MockAction {
            action_type: "service".to_string(),
        };

        assert!(engine.authorize(&action, &client).is_ok());
    }
}
