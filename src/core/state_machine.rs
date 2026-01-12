//! State Machine - Enforces valid agent state transitions
//!
//! The agent can only be in one state at a time, and transitions
//! must follow the defined rules to ensure safety.

use std::sync::atomic::{AtomicU8, Ordering};



use super::CoreError;

/// Agent states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentState {
    /// Initial state during startup
    Init = 0,
    /// Recovering from a previous crash
    Recovering = 1,
    /// Ready and accepting events
    Ready = 2,
    /// Draining in-flight actions before shutdown
    Draining = 3,
    /// Stopped, about to exit
    Stopped = 4,
}

impl TryFrom<u8> for AgentState {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AgentState::Init),
            1 => Ok(AgentState::Recovering),
            2 => Ok(AgentState::Ready),
            3 => Ok(AgentState::Draining),
            4 => Ok(AgentState::Stopped),
            _ => Err(()),
        }
    }
}

/// State machine that enforces valid transitions
pub struct StateMachine {
    state: AtomicU8,
}

impl StateMachine {
    /// Create a new state machine in Init state
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(AgentState::Init as u8),
        }
    }

    /// Get the current state
    pub fn current(&self) -> AgentState {
        AgentState::try_from(self.state.load(Ordering::SeqCst)).unwrap_or(AgentState::Init)
    }

    /// Attempt to transition to a new state
    pub fn transition_to(&self, new_state: AgentState) -> Result<(), CoreError> {
        let current = self.current();

        if !Self::is_valid_transition(current, new_state) {
            return Err(CoreError::InvalidTransition {
                from: current,
                to: new_state,
            });
        }

        self.state.store(new_state as u8, Ordering::SeqCst);
        tracing::info!("State transition: {:?} -> {:?}", current, new_state);

        Ok(())
    }

    /// Check if a transition is valid
    fn is_valid_transition(from: AgentState, to: AgentState) -> bool {
        use AgentState::*;

        matches!(
            (from, to),
            // Normal flow
            (Init, Recovering)
                | (Recovering, Ready)
                | (Ready, Draining)
                | (Draining, Stopped)
                // Skip recovery if WAL is clean
                | (Init, Ready)
                // Emergency shutdown from any state
                | (_, Stopped)
        )
    }

    /// Check if the agent is accepting new events
    pub fn is_accepting_events(&self) -> bool {
        self.current() == AgentState::Ready
    }

    /// Check if the agent is shutting down
    pub fn is_shutting_down(&self) -> bool {
        matches!(self.current(), AgentState::Draining | AgentState::Stopped)
    }

    /// Begin shutdown sequence
    pub fn begin_shutdown(&self) -> Result<(), CoreError> {
        let current = self.current();
        tracing::debug!("Beginning shutdown from state {:?}", current);

        match current {
            AgentState::Ready => self.transition_to(AgentState::Draining),
            AgentState::Draining | AgentState::Stopped => Ok(()), // Already shutting down
            _ => self.transition_to(AgentState::Stopped), // Emergency shutdown
        }
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        let sm = StateMachine::new();

        assert!(sm.transition_to(AgentState::Recovering).is_ok());
        assert!(sm.transition_to(AgentState::Ready).is_ok());
        assert!(sm.transition_to(AgentState::Draining).is_ok());
        assert!(sm.transition_to(AgentState::Stopped).is_ok());
    }

    #[test]
    fn test_invalid_transition() {
        let sm = StateMachine::new();

        // Can't go from Init to Draining
        assert!(sm.transition_to(AgentState::Draining).is_err());
    }

    #[test]
    fn test_emergency_shutdown() {
        let sm = StateMachine::new();
        sm.transition_to(AgentState::Recovering).unwrap();

        // Can always go to Stopped
        assert!(sm.transition_to(AgentState::Stopped).is_ok());
    }
}
