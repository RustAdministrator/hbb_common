#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeTransportStats {
    pub transport: String,
    pub direct: bool,
    pub peer_address: String,
    pub connection_uptime_ms: u64,
    pub rtt_us: u64,
    pub input_latency_us: u64,
    pub video_capture_to_display_us: u64,
    pub audio_capture_to_playback_us: u64,
    pub encoder_latency_us: u64,
    pub decoder_latency_us: u64,
    pub frame_reassembly_latency_us: u64,
    pub audio_jitter_buffer_ms: u32,
    pub video_bitrate_kbps: u32,
    pub audio_bitrate_kbps: u32,
    pub fps: u16,
    pub dropped_frames: u64,
    pub packet_loss_ppm: u32,
    pub datagram_drops: u64,
    pub decoder_queue_depth: u32,
    pub resolution_width: u16,
    pub resolution_height: u16,
    pub current_mtu: u16,
    pub max_datagram_payload: u16,
    pub reconnect_attempts: u32,
}

impl RuntimeTransportStats {
    pub fn validate(&self) -> bool {
        self.transport.len() <= 32
            && self.peer_address.len() <= 128
            && self.packet_loss_ppm <= 1_000_000
            && self.resolution_width <= 16_384
            && self.resolution_height <= 16_384
            && self.fps <= 240
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_statistics_reject_impossible_values() {
        let mut stats = RuntimeTransportStats::default();
        assert!(stats.validate());
        stats.packet_loss_ppm = 1_000_001;
        assert!(!stats.validate());
    }
}
