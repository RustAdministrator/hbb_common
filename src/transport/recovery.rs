use super::input::{ReliableInputEvent, ReliableInputReceiver};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct ReconnectPolicy {
    pub initial_delay: Duration,
    pub maximum_delay: Duration,
    pub maximum_attempts: u32,
    pub jitter_percent: u8,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            maximum_delay: Duration::from_secs(8),
            maximum_attempts: 8,
            jitter_percent: 20,
        }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RecoveryError {
    #[error("reconnect policy is invalid")]
    InvalidPolicy,
    #[error("automatic reconnect attempts are exhausted")]
    AttemptsExhausted,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DisconnectActions {
    pub input_releases: Vec<ReliableInputEvent>,
    pub discard_video_and_audio: bool,
    pub request_fresh_keyframe: bool,
    pub reauthenticate: bool,
    pub renegotiate_capabilities: bool,
    pub resume_files_after_integrity_check: bool,
}

pub struct ReconnectState {
    policy: ReconnectPolicy,
    attempts: u32,
    generation: u64,
}

impl ReconnectState {
    pub fn new(policy: ReconnectPolicy) -> Result<Self, RecoveryError> {
        if policy.initial_delay.is_zero()
            || policy.maximum_delay < policy.initial_delay
            || policy.maximum_attempts == 0
            || policy.jitter_percent > 50
        {
            return Err(RecoveryError::InvalidPolicy);
        }
        Ok(Self {
            policy,
            attempts: 0,
            generation: 1,
        })
    }

    pub fn on_disconnect(&mut self, input: &mut ReliableInputReceiver) -> DisconnectActions {
        self.generation = self.generation.saturating_add(1);
        DisconnectActions {
            input_releases: input.release_all(),
            discard_video_and_audio: true,
            request_fresh_keyframe: true,
            reauthenticate: true,
            renegotiate_capabilities: true,
            resume_files_after_integrity_check: true,
        }
    }

    pub fn next_delay(&mut self, jitter_sample: u64) -> Result<Duration, RecoveryError> {
        if self.attempts >= self.policy.maximum_attempts {
            return Err(RecoveryError::AttemptsExhausted);
        }
        let exponent = self.attempts.min(31);
        let base_millis = self
            .policy
            .initial_delay
            .as_millis()
            .saturating_mul(1u128 << exponent)
            .min(self.policy.maximum_delay.as_millis());
        self.attempts += 1;
        let range = base_millis.saturating_mul(self.policy.jitter_percent as u128) / 100;
        let width = range.saturating_mul(2).saturating_add(1);
        let offset = if width == 0 {
            0
        } else {
            (jitter_sample as u128 % width) as i128 - range as i128
        };
        let jittered = (base_millis as i128 + offset).max(0) as u128;
        Ok(Duration::from_millis(
            jittered.min(u128::from(u64::MAX)) as u64
        ))
    }

    pub fn manual_delay(&self) -> Duration {
        Duration::ZERO
    }

    pub fn on_connected(&mut self) {
        self.attempts = 0;
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::input::{encode_reliable_input, ReliableInputEvent};

    #[test]
    fn backoff_is_bounded_and_exhausts() {
        let mut state = ReconnectState::new(ReconnectPolicy {
            initial_delay: Duration::from_millis(100),
            maximum_delay: Duration::from_millis(400),
            maximum_attempts: 4,
            jitter_percent: 0,
        })
        .unwrap();
        assert_eq!(state.next_delay(0).unwrap(), Duration::from_millis(100));
        assert_eq!(state.next_delay(0).unwrap(), Duration::from_millis(200));
        assert_eq!(state.next_delay(0).unwrap(), Duration::from_millis(400));
        assert_eq!(state.next_delay(0).unwrap(), Duration::from_millis(400));
        assert_eq!(state.next_delay(0), Err(RecoveryError::AttemptsExhausted));
    }

    #[test]
    fn disconnect_releases_input_and_requires_fresh_media_state() {
        let mut input = ReliableInputReceiver::new();
        input
            .apply(
                1,
                &encode_reliable_input(ReliableInputEvent::Key {
                    key_code: 10,
                    pressed: true,
                    modifiers: 0,
                }),
            )
            .unwrap();
        let mut state = ReconnectState::new(ReconnectPolicy::default()).unwrap();
        let actions = state.on_disconnect(&mut input);
        assert_eq!(actions.input_releases.len(), 1);
        assert!(actions.discard_video_and_audio);
        assert!(actions.request_fresh_keyframe);
        assert!(actions.reauthenticate);
        assert!(actions.renegotiate_capabilities);
    }
}
