//! Action Registry - Registration and lookup of action types
//!
//! Provides a registry for deserializing actions from the WAL.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::debug;

use super::action::Action;
use super::firewall::FirewallAction;
use super::services::ServiceAction;
use super::ActionError;

/// Factory function for creating actions from serialized data
pub type ActionFactory = Arc<dyn Fn(&[u8]) -> Result<Box<dyn Action>, ActionError> + Send + Sync>;

/// Registry of action types for serialization/deserialization
pub struct ActionRegistry {
    factories: HashMap<String, ActionFactory>,
}

impl ActionRegistry {
    /// Create a new registry with built-in action types
    pub fn new() -> Self {
        let mut registry = Self {
            factories: HashMap::new(),
        };

        // Register built-in action types
        registry.register_builtin_actions();

        registry
    }

    /// Register built-in action types
    fn register_builtin_actions(&mut self) {
        // Register firewall action
        self.register("firewall", Arc::new(|data: &[u8]| {
            let action: FirewallAction = serde_json::from_slice(data)
                .map_err(|e| ActionError::Serialization(e.to_string()))?;
            Ok(Box::new(action) as Box<dyn Action>)
        }));

        // Register service action
        self.register("service", Arc::new(|data: &[u8]| {
            let action: ServiceAction = serde_json::from_slice(data)
                .map_err(|e| ActionError::Serialization(e.to_string()))?;
            Ok(Box::new(action) as Box<dyn Action>)
        }));
    }

    /// Register a new action type
    pub fn register(&mut self, action_type: &str, factory: ActionFactory) {
        debug!("Registering action type: {}", action_type);
        self.factories.insert(action_type.to_string(), factory);
    }

    /// Deserialize an action from bytes
    pub fn deserialize(
        &self,
        action_type: &str,
        data: &[u8],
    ) -> Result<Box<dyn Action>, ActionError> {
        let factory = self
            .factories
            .get(action_type)
            .ok_or_else(|| ActionError::UnknownAction(action_type.to_string()))?;

        factory(data)
    }

    /// Get all registered action types
    pub fn action_types(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }

    /// Check if an action type is registered
    pub fn is_registered(&self, action_type: &str) -> bool {
        self.factories.contains_key(action_type)
    }
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_registration() {
        let registry = ActionRegistry::new();

        assert!(registry.is_registered("firewall"));
        assert!(registry.is_registered("service"));
        assert!(!registry.is_registered("unknown"));
    }

    #[test]
    fn test_deserialize_firewall() {
        use super::super::firewall::{FirewallOperation, FirewallRule, Protocol};

        let registry = ActionRegistry::new();

        let rule = FirewallRule::allow_port(443, Protocol::Tcp);
        let action = FirewallAction::new(FirewallOperation::Add, rule);
        let serialized = action.serialize().unwrap();

        let deserialized = registry.deserialize("firewall", &serialized).unwrap();
        assert_eq!(deserialized.action_type(), "firewall");
    }
}
