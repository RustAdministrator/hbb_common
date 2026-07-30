#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AdaptationMetrics {
    pub quic_rtt_ms: f32,
    pub packet_loss_percent: f32,
    pub datagram_drop_percent: f32,
    pub frame_completion_percent: f32,
    pub decoder_queue_depth: u32,
    pub input_latency_ms: f32,
    pub send_queue_bytes: u64,
    pub estimated_bandwidth_kbps: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MediaTarget {
    pub video_bitrate_kbps: u32,
    pub max_fps: u16,
    pub resolution_scale_percent: u8,
    pub keyframe_interval_frames: u16,
    pub audio_bitrate_kbps: u16,
    pub file_bitrate_kbps: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct AdaptationLimits {
    pub minimum_video_bitrate_kbps: u32,
    pub maximum_video_bitrate_kbps: u32,
    pub maximum_fps: u16,
    pub maximum_audio_bitrate_kbps: u16,
    pub maximum_file_bitrate_kbps: u32,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum AdaptationError {
    #[error("transport adaptation limits are invalid")]
    InvalidLimits,
}

pub struct BandwidthAdapter {
    limits: AdaptationLimits,
    target: MediaTarget,
}

impl BandwidthAdapter {
    pub fn new(limits: AdaptationLimits) -> Result<Self, AdaptationError> {
        if limits.minimum_video_bitrate_kbps == 0
            || limits.maximum_video_bitrate_kbps < limits.minimum_video_bitrate_kbps
            || limits.maximum_fps == 0
            || limits.maximum_audio_bitrate_kbps == 0
        {
            return Err(AdaptationError::InvalidLimits);
        }
        Ok(Self {
            target: MediaTarget {
                video_bitrate_kbps: limits.maximum_video_bitrate_kbps,
                max_fps: limits.maximum_fps,
                resolution_scale_percent: 100,
                keyframe_interval_frames: limits.maximum_fps.saturating_mul(2).max(1),
                audio_bitrate_kbps: limits.maximum_audio_bitrate_kbps,
                file_bitrate_kbps: limits.maximum_file_bitrate_kbps,
            },
            limits,
        })
    }

    pub fn update(&mut self, metrics: AdaptationMetrics) -> MediaTarget {
        let severe = metrics.packet_loss_percent >= 8.0
            || metrics.datagram_drop_percent >= 10.0
            || metrics.frame_completion_percent < 80.0
            || metrics.decoder_queue_depth >= 6
            || metrics.quic_rtt_ms >= 200.0;
        let constrained = severe
            || metrics.packet_loss_percent >= 3.0
            || metrics.datagram_drop_percent >= 5.0
            || metrics.frame_completion_percent < 92.0
            || metrics.decoder_queue_depth >= 3
            || metrics.input_latency_ms >= 120.0
            || metrics.send_queue_bytes >= 2 * 1024 * 1024;

        let bandwidth_budget = metrics
            .estimated_bandwidth_kbps
            .saturating_mul(if constrained { 65 } else { 80 })
            / 100;
        if constrained {
            let decrease_percent = if severe { 65 } else { 82 };
            self.target.video_bitrate_kbps = self
                .target
                .video_bitrate_kbps
                .saturating_mul(decrease_percent)
                / 100;
        } else {
            let increase = (self.target.video_bitrate_kbps / 20).max(100);
            self.target.video_bitrate_kbps =
                self.target.video_bitrate_kbps.saturating_add(increase);
        }
        if bandwidth_budget > 0 {
            self.target.video_bitrate_kbps = self.target.video_bitrate_kbps.min(bandwidth_budget);
        }
        self.target.video_bitrate_kbps = self.target.video_bitrate_kbps.clamp(
            self.limits.minimum_video_bitrate_kbps,
            self.limits.maximum_video_bitrate_kbps,
        );

        self.target.max_fps = if severe {
            self.limits.maximum_fps.min(20)
        } else if constrained {
            self.limits.maximum_fps.min(30)
        } else {
            self.limits.maximum_fps
        };
        self.target.resolution_scale_percent = if severe {
            50
        } else if constrained {
            75
        } else {
            100
        };
        self.target.keyframe_interval_frames = if metrics.datagram_drop_percent >= 5.0 {
            self.target.max_fps.max(1)
        } else {
            self.target.max_fps.saturating_mul(2).max(1)
        };
        self.target.audio_bitrate_kbps = if severe {
            self.limits.maximum_audio_bitrate_kbps.min(48)
        } else {
            self.limits.maximum_audio_bitrate_kbps
        };

        // File traffic remains a small, separately rate-limited share of the measured path.
        self.target.file_bitrate_kbps = metrics
            .estimated_bandwidth_kbps
            .saturating_mul(if constrained { 5 } else { 20 })
            / 100;
        self.target.file_bitrate_kbps = self
            .target
            .file_bitrate_kbps
            .min(self.limits.maximum_file_bitrate_kbps);
        self.target
    }

    pub fn target(&self) -> MediaTarget {
        self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> BandwidthAdapter {
        BandwidthAdapter::new(AdaptationLimits {
            minimum_video_bitrate_kbps: 500,
            maximum_video_bitrate_kbps: 50_000,
            maximum_fps: 60,
            maximum_audio_bitrate_kbps: 96,
            maximum_file_bitrate_kbps: 20_000,
        })
        .unwrap()
    }

    #[test]
    fn severe_loss_reduces_disposable_media_before_interactive_channels() {
        let mut adapter = adapter();
        let target = adapter.update(AdaptationMetrics {
            packet_loss_percent: 10.0,
            datagram_drop_percent: 12.0,
            frame_completion_percent: 70.0,
            estimated_bandwidth_kbps: 10_000,
            ..Default::default()
        });
        assert!(target.video_bitrate_kbps <= 6_500);
        assert_eq!(target.max_fps, 20);
        assert_eq!(target.resolution_scale_percent, 50);
        assert_eq!(target.file_bitrate_kbps, 500);
    }

    #[test]
    fn healthy_path_recovers_gradually_with_headroom() {
        let mut adapter = adapter();
        adapter.update(AdaptationMetrics {
            packet_loss_percent: 10.0,
            frame_completion_percent: 70.0,
            estimated_bandwidth_kbps: 10_000,
            ..Default::default()
        });
        let degraded = adapter.target().video_bitrate_kbps;
        let recovered = adapter.update(AdaptationMetrics {
            frame_completion_percent: 100.0,
            estimated_bandwidth_kbps: 50_000,
            ..Default::default()
        });
        assert!(recovered.video_bitrate_kbps > degraded);
        assert!(recovered.video_bitrate_kbps < 50_000);
    }
}
