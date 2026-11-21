//! The sending rate of the file channel on a QUIC connection.
//!
//! Files share the connection's congestion window with video. The streams have priorities,
//! but the window is one: file bytes that fill it make a video datagram wait for
//! acknowledgements, and a bulk transfer drives the congestion controller to loss on a narrow
//! link, where it is the video datagrams that get lost. A fixed cap protects video and wastes
//! a fast link; no cap does the opposite.
//!
//! The automatic mode follows the idea of background congestion control (LEDBAT, RFC 6817)
//! at the application level: while video is flowing the file channel gives way as soon as the
//! round trip time grows over its recent minimum, and takes what is free otherwise. Without
//! video there is nothing to protect, and no limiter runs.
//!
//! Nothing here is on the wire. A peer in automatic mode advertises the value that has
//! always meant "no cap" and limits what it sends itself.

use std::{
    collections::VecDeque,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

/// The cap the automatic mode starts from when video starts to flow. It is the fixed cap of
/// the builds before this mode existed.
pub const FILE_RATE_START_KBPS: u64 = 20_000;
/// The automatic mode never goes below this.
pub const FILE_RATE_FLOOR_KBPS: u64 = 1_000;
/// How often the cap is reconsidered.
pub const FILE_RATE_TICK: Duration = Duration::from_millis(250);
/// The round trip time may exceed its recent minimum by this much before the file channel
/// gives way. A starting value: it has not been tuned on a real narrow link yet.
pub const FILE_RATE_RTT_EXCESS: Duration = Duration::from_millis(25);
/// How far back the minimum round trip time is looked for.
pub const FILE_RATE_RTT_WINDOW: Duration = Duration::from_secs(30);
/// Video counts as flowing for this long after the last frame was sent or received.
pub const FILE_RATE_VIDEO_IDLE: Duration = Duration::from_secs(2);
/// The limiter lets the channel run ahead of its schedule by this much before it sleeps, so
/// that it does not sleep for every block.
pub const FILE_LIMITER_MAX_DEBT: Duration = Duration::from_millis(5);
/// The value a peer advertises for "no cap". It is the value `0` has always been sent as.
pub const FILE_RATE_UNLIMITED_KBPS: u32 = 1_000_000;

/// What the option `quic-file-bandwidth-mbps` asks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileBandwidthLimit {
    /// No cap without video; with video the cap follows the round trip time. The default.
    Auto,
    /// No cap (`0`).
    Unlimited,
    /// A fixed cap in megabits per second.
    Mbps(u32),
}

impl FileBandwidthLimit {
    /// The largest fixed cap the option accepts, in megabits per second.
    pub const MAX_MBPS: u32 = 10_000;

    /// Reads the option: empty or `auto` is automatic, `0` is no cap, a number up to
    /// [`Self::MAX_MBPS`] is a fixed cap. Anything else is `None`.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("auto") {
            return Some(Self::Auto);
        }
        match value.parse::<u32>() {
            Ok(0) => Some(Self::Unlimited),
            Ok(mbps) if mbps <= Self::MAX_MBPS => Some(Self::Mbps(mbps)),
            _ => None,
        }
    }

    /// What is put into the session offer. The automatic mode limits itself, so it
    /// advertises "no cap": two such peers agree on no cap and each runs its own controller.
    /// A peer of an older build advertises its fixed cap, and the agreement is that cap.
    pub fn advertised_kbps(self) -> u32 {
        match self {
            Self::Auto | Self::Unlimited => FILE_RATE_UNLIMITED_KBPS,
            Self::Mbps(mbps) => mbps.saturating_mul(1_000),
        }
    }
}

/// How the file channel of one connection is limited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRatePlan {
    /// The cap both peers agreed on; `None` when they agreed on no cap.
    pub ceiling_kbps: Option<u64>,
    /// Whether this side also runs the controller below that ceiling.
    pub automatic: bool,
}

impl FileRatePlan {
    pub fn new(local: FileBandwidthLimit, agreed_kbps: u32) -> Self {
        Self {
            ceiling_kbps: (agreed_kbps < FILE_RATE_UNLIMITED_KBPS)
                .then_some(u64::from(agreed_kbps)),
            automatic: local == FileBandwidthLimit::Auto,
        }
    }
}

/// What the controller looks at once per [`FILE_RATE_TICK`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileRateSignals {
    /// A video frame was sent or received within [`FILE_RATE_VIDEO_IDLE`].
    pub video_active: bool,
    /// The connection's smoothed round trip time.
    pub smoothed_rtt: Duration,
    /// Its minimum over [`FILE_RATE_RTT_WINDOW`].
    pub min_rtt: Duration,
    /// Video frames that the datagram path refused since the last tick.
    pub video_frames_rejected: u64,
    /// Times the congestion controller reduced its window since the last tick.
    pub congestion_events: u64,
    /// The file channel sent close to its cap since the last tick: the cap, and not the disk
    /// or the peer, is what held it back.
    pub cap_was_binding: bool,
}

impl FileRateSignals {
    /// Whether the path shows that it is carrying more than it can.
    pub fn congested(&self) -> bool {
        self.smoothed_rtt > self.min_rtt.saturating_add(FILE_RATE_RTT_EXCESS)
            || self.video_frames_rejected > 0
            || self.congestion_events > 0
    }
}

/// One step of the automatic mode: the cap for the next interval, in kilobits per second.
/// `None` is "no limiter".
///
/// - No video: no limiter. The next time video flows the cap starts again from
///   [`FILE_RATE_START_KBPS`].
/// - Congestion: the cap is halved, down to [`FILE_RATE_FLOOR_KBPS`].
/// - Otherwise the cap grows by a quarter, but only when it was the cap that held the
///   channel back; a cap that nothing reaches is left where it is.
pub fn next_file_rate_kbps(current: Option<u64>, signals: &FileRateSignals) -> Option<u64> {
    if !signals.video_active {
        return None;
    }
    let Some(current) = current else {
        return Some(FILE_RATE_START_KBPS);
    };
    if signals.congested() {
        return Some((current / 2).max(FILE_RATE_FLOOR_KBPS));
    }
    if signals.cap_was_binding {
        return Some(current.saturating_add((current / 4).max(FILE_RATE_FLOOR_KBPS)));
    }
    Some(current)
}

/// The minimum of the round trip time over a sliding window.
#[derive(Debug, Default)]
pub struct MinRttWindow {
    // Increasing in both time and value; the front is the minimum.
    samples: VecDeque<(Instant, Duration)>,
}

impl MinRttWindow {
    /// Adds a sample and returns the minimum over the last [`FILE_RATE_RTT_WINDOW`].
    pub fn update(&mut self, now: Instant, rtt: Duration) -> Duration {
        while self.samples.back().is_some_and(|(_, value)| *value >= rtt) {
            self.samples.pop_back();
        }
        self.samples.push_back((now, rtt));
        while self
            .samples
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > FILE_RATE_RTT_WINDOW)
        {
            self.samples.pop_front();
        }
        self.samples.front().map(|(_, value)| *value).unwrap_or(rtt)
    }
}

/// What the controller and the writer of the file channel share.
#[derive(Debug, Default)]
pub struct FileRateShared {
    // Zero is "none" in both.
    ceiling_kbps: AtomicU64,
    controller_kbps: AtomicU64,
    sent_bytes: AtomicU64,
}

fn load_kbps(value: &AtomicU64) -> Option<u64> {
    Some(value.load(Ordering::Relaxed)).filter(|kbps| *kbps > 0)
}

fn store_kbps(value: &AtomicU64, kbps: Option<u64>) {
    value.store(kbps.map(|kbps| kbps.max(1)).unwrap_or(0), Ordering::Relaxed);
}

impl FileRateShared {
    pub fn new(plan: &FileRatePlan) -> Self {
        let shared = Self::default();
        shared.set_ceiling_kbps(plan.ceiling_kbps);
        shared
    }

    /// The cap the writer applies now: the lower of the agreed ceiling and what the
    /// controller allows. `None` is "no cap".
    pub fn cap_kbps(&self) -> Option<u64> {
        match (
            load_kbps(&self.ceiling_kbps),
            load_kbps(&self.controller_kbps),
        ) {
            (Some(ceiling), Some(controller)) => Some(ceiling.min(controller)),
            (ceiling, controller) => ceiling.or(controller),
        }
    }

    pub fn set_ceiling_kbps(&self, kbps: Option<u64>) {
        store_kbps(&self.ceiling_kbps, kbps);
    }

    pub fn controller_kbps(&self) -> Option<u64> {
        load_kbps(&self.controller_kbps)
    }

    pub fn set_controller_kbps(&self, kbps: Option<u64>) {
        store_kbps(&self.controller_kbps, kbps);
    }

    pub fn add_sent(&self, bytes: usize) {
        self.sent_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn sent_bytes(&self) -> u64 {
        self.sent_bytes.load(Ordering::Relaxed)
    }
}

/// Whether `sent_bytes` in `interval` is close enough to `cap_kbps` to say that the cap is
/// what held the channel back.
pub fn cap_was_binding(sent_bytes: u64, interval: Duration, cap_kbps: Option<u64>) -> bool {
    let Some(cap_kbps) = cap_kbps else {
        return false;
    };
    let allowed_bytes = u128::from(cap_kbps) * 1_000 / 8 * interval.as_micros() / 1_000_000;
    // Four fifths: the limiter works in whole messages.
    u128::from(sent_bytes) * 5 >= allowed_bytes * 4
}

/// Paces the messages of the file channel to a cap.
///
/// It keeps the time at which everything sent so far is paid for at the current cap. A
/// message is sent at once while that time is no more than [`FILE_LIMITER_MAX_DEBT`] ahead;
/// beyond that the limiter sleeps until the debt is paid. Without a cap it never sleeps.
#[derive(Debug, Default)]
pub struct FileRateLimiter {
    paid_until: Option<Instant>,
}

impl FileRateLimiter {
    /// Accounts for a message of `bytes` that is about to be sent at `now`. Returns the time
    /// to wait for before sending it, when the channel is too far ahead of its schedule.
    pub fn charge(&mut self, now: Instant, bytes: usize, cap_kbps: Option<u64>) -> Option<Instant> {
        let Some(cap_kbps) = cap_kbps.filter(|cap| *cap > 0) else {
            self.paid_until = None;
            return None;
        };
        // Time that passed without anything to send is not credit for a later burst.
        let paid_until = self.paid_until.filter(|paid_until| *paid_until > now);
        let wait_until = paid_until.filter(|paid_until| *paid_until > now + FILE_LIMITER_MAX_DEBT);
        let cost_us = (bytes as u128)
            .saturating_mul(8_000)
            .div_ceil(u128::from(cap_kbps))
            .min(u128::from(u64::MAX)) as u64;
        self.paid_until = Some(paid_until.unwrap_or(now) + Duration::from_micros(cost_us));
        wait_until
    }

    /// Call before sending a message of `bytes`: sleeps when [`Self::charge`] says so.
    pub async fn pace(&mut self, bytes: usize, cap_kbps: Option<u64>) {
        if let Some(until) = self.charge(Instant::now(), bytes, cap_kbps) {
            tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: usize = 128 * 1024;

    fn signals(video_active: bool) -> FileRateSignals {
        FileRateSignals {
            video_active,
            smoothed_rtt: Duration::from_millis(20),
            min_rtt: Duration::from_millis(20),
            cap_was_binding: true,
            ..Default::default()
        }
    }

    #[test]
    fn option_values() {
        use FileBandwidthLimit::*;
        for (value, expected) in [
            ("", Some(Auto)),
            ("auto", Some(Auto)),
            (" AUTO ", Some(Auto)),
            ("0", Some(Unlimited)),
            ("20", Some(Mbps(20))),
            ("10000", Some(Mbps(10_000))),
            ("10001", None),
            ("-1", None),
            ("fast", None),
            ("1.5", None),
        ] {
            assert_eq!(FileBandwidthLimit::parse(value), expected, "{:?}", value);
        }
        assert_eq!(Auto.advertised_kbps(), FILE_RATE_UNLIMITED_KBPS);
        assert_eq!(Unlimited.advertised_kbps(), FILE_RATE_UNLIMITED_KBPS);
        assert_eq!(Mbps(20).advertised_kbps(), 20_000);
    }

    #[test]
    fn plan_for_each_pair_of_peers() {
        use FileBandwidthLimit::*;
        let agreed = |local: FileBandwidthLimit, remote_kbps: u32| {
            FileRatePlan::new(local, local.advertised_kbps().min(remote_kbps))
        };
        let cap = |plan: &FileRatePlan, controller: Option<u64>| {
            let shared = FileRateShared::new(plan);
            shared.set_controller_kbps(controller);
            shared.cap_kbps()
        };
        // Two peers in automatic mode: no ceiling, each runs its controller.
        let plan = agreed(Auto, Auto.advertised_kbps());
        assert_eq!((plan.ceiling_kbps, plan.automatic), (None, true));
        assert_eq!(cap(&plan, None), None);
        assert_eq!(cap(&plan, Some(40_000)), Some(40_000));
        // A peer of an older build advertises its fixed 20 Mbit/s: that stays the ceiling.
        let plan = agreed(Auto, 20_000);
        assert_eq!((plan.ceiling_kbps, plan.automatic), (Some(20_000), true));
        assert_eq!(cap(&plan, None), Some(20_000));
        assert_eq!(cap(&plan, Some(80_000)), Some(20_000));
        assert_eq!(cap(&plan, Some(5_000)), Some(5_000));
        // A number set here is a fixed cap, whatever the peer runs.
        let plan = agreed(Mbps(50), Auto.advertised_kbps());
        assert_eq!((plan.ceiling_kbps, plan.automatic), (Some(50_000), false));
        assert_eq!(cap(&plan, None), Some(50_000));
        // "No cap" here and automatic there: nothing limits this side.
        let plan = agreed(Unlimited, Auto.advertised_kbps());
        assert_eq!((plan.ceiling_kbps, plan.automatic), (None, false));
        assert_eq!(cap(&plan, None), None);
    }

    #[test]
    fn controller_steps() {
        let clear = signals(true);
        let rtt_grew = FileRateSignals {
            smoothed_rtt: Duration::from_millis(46),
            ..clear
        };
        let rtt_within_threshold = FileRateSignals {
            smoothed_rtt: Duration::from_millis(45),
            ..clear
        };
        let video_refused = FileRateSignals {
            video_frames_rejected: 1,
            ..clear
        };
        let window_reduced = FileRateSignals {
            congestion_events: 1,
            ..clear
        };
        let not_binding = FileRateSignals {
            cap_was_binding: false,
            ..clear
        };
        // (current cap, signals, next cap)
        let table: [(Option<u64>, FileRateSignals, Option<u64>); 12] = [
            // No video: no limiter, whatever the path looks like.
            (None, signals(false), None),
            (Some(80_000), signals(false), None),
            (
                Some(80_000),
                FileRateSignals {
                    video_active: false,
                    ..rtt_grew
                },
                None,
            ),
            // Video starts: the cap of the earlier builds.
            (None, clear, Some(20_000)),
            (None, rtt_grew, Some(20_000)),
            // A clear path: a quarter more.
            (Some(20_000), clear, Some(25_000)),
            (Some(20_000), rtt_within_threshold, Some(25_000)),
            // A cap that nothing reaches stays.
            (Some(20_000), not_binding, Some(20_000)),
            // Each sign of congestion halves the cap.
            (Some(20_000), rtt_grew, Some(10_000)),
            (Some(20_000), video_refused, Some(10_000)),
            (Some(20_000), window_reduced, Some(10_000)),
            // The floor.
            (Some(1_500), rtt_grew, Some(1_000)),
        ];
        for (index, (current, signals, expected)) in table.iter().enumerate() {
            assert_eq!(
                next_file_rate_kbps(*current, signals),
                *expected,
                "row {}",
                index
            );
        }
    }

    #[test]
    fn controller_recovers_and_reaches_a_fast_link_in_seconds() {
        let clear = signals(true);
        let congested = FileRateSignals {
            congestion_events: 1,
            ..clear
        };
        // Down to the floor and never below.
        let mut cap = Some(FILE_RATE_START_KBPS);
        for _ in 0..20 {
            cap = next_file_rate_kbps(cap, &congested);
        }
        assert_eq!(cap, Some(FILE_RATE_FLOOR_KBPS));
        // Back up when the path is clear: one gigabit per second within ten seconds.
        let mut ticks = 0u32;
        while cap.is_some_and(|cap| cap < 1_000_000) {
            cap = next_file_rate_kbps(cap, &clear);
            ticks += 1;
            assert!(ticks < 1_000, "the cap does not grow");
        }
        assert!(
            FILE_RATE_TICK * ticks < Duration::from_secs(10),
            "{} ticks",
            ticks
        );
        // No overflow however long the path stays clear.
        let mut cap = Some(u64::MAX - 1);
        cap = next_file_rate_kbps(cap, &clear);
        assert_eq!(cap, Some(u64::MAX));
    }

    #[test]
    fn minimum_round_trip_time_follows_the_window() {
        let mut window = MinRttWindow::default();
        let start = Instant::now();
        let ms = Duration::from_millis;
        assert_eq!(window.update(start, ms(30)), ms(30));
        assert_eq!(window.update(start + ms(250), ms(20)), ms(20));
        assert_eq!(window.update(start + ms(500), ms(60)), ms(20));
        // The low sample leaves the window; the minimum is the lowest that is still in it.
        let later = start + ms(250) + FILE_RATE_RTT_WINDOW + ms(1);
        assert_eq!(window.update(later, ms(80)), ms(60));
        let much_later = later + FILE_RATE_RTT_WINDOW + ms(1);
        assert_eq!(window.update(much_later, ms(90)), ms(90));
    }

    #[test]
    fn binding_cap_is_recognised() {
        let tick = FILE_RATE_TICK;
        // 20 Mbit/s for 250 ms is 625,000 bytes.
        assert!(cap_was_binding(625_000, tick, Some(20_000)));
        assert!(cap_was_binding(500_000, tick, Some(20_000)));
        assert!(!cap_was_binding(499_999, tick, Some(20_000)));
        assert!(!cap_was_binding(0, tick, Some(20_000)));
        assert!(!cap_was_binding(u64::MAX, tick, None));
    }

    /// Sends `count` messages through the limiter on a clock that only the limiter moves:
    /// a wait takes exactly as long as the limiter asks for and nothing else takes time.
    /// Returns the time at which the last message is sent.
    fn send_on_a_stopped_clock(
        limiter: &mut FileRateLimiter,
        start: Instant,
        count: usize,
        cap_kbps: Option<u64>,
    ) -> Instant {
        let mut now = start;
        for _ in 0..count {
            if let Some(until) = limiter.charge(now, BLOCK, cap_kbps) {
                assert!(until > now);
                now = until;
            }
        }
        now
    }

    #[test]
    fn no_cap_never_waits() {
        let mut limiter = FileRateLimiter::default();
        let start = Instant::now();
        assert_eq!(
            send_on_a_stopped_clock(&mut limiter, start, 10_000, None),
            start,
            "the limiter asked for a wait without a cap"
        );
        // Zero is "no cap" too.
        assert_eq!(limiter.charge(start, BLOCK, Some(0)), None);
    }

    #[tokio::test]
    async fn no_cap_does_not_sleep_in_the_writer_path() {
        // The same through the call the channel writer makes, on the real clock: ten
        // thousand blocks take no measurable time.
        let mut limiter = FileRateLimiter::default();
        let start = Instant::now();
        for _ in 0..10_000 {
            limiter.pace(BLOCK, None).await;
        }
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn cap_sets_the_average_rate() {
        // A block of 128 KiB at 20 Mbit/s costs 52.4288 ms. The first one is sent at once
        // and each of the others when the one before it is paid for.
        let mut limiter = FileRateLimiter::default();
        let start = Instant::now();
        let last = send_on_a_stopped_clock(&mut limiter, start, 1000, Some(20_000));
        assert_eq!(last - start, Duration::from_micros(52_429 * 999));
    }

    #[test]
    fn small_debt_does_not_wait() {
        // At 1 Gbit/s a block costs about a millisecond: several go out before one wait.
        let mut limiter = FileRateLimiter::default();
        let start = Instant::now();
        let mut sent_without_waiting = 0;
        while limiter.charge(start, BLOCK, Some(1_000_000)).is_none() {
            sent_without_waiting += 1;
            assert!(sent_without_waiting < 100);
        }
        assert!(sent_without_waiting >= 5, "{}", sent_without_waiting);
        // The average is still the cap: 1000 more blocks take about 1.05 s.
        let mut limiter = FileRateLimiter::default();
        let last = send_on_a_stopped_clock(&mut limiter, start, 1000, Some(1_000_000));
        let elapsed = last - start;
        assert!(
            elapsed >= Duration::from_millis(1_030) && elapsed <= Duration::from_millis(1_050),
            "{:?}",
            elapsed
        );
    }

    #[test]
    fn idle_time_is_not_credit() {
        let mut limiter = FileRateLimiter::default();
        let start = Instant::now();
        assert_eq!(limiter.charge(start, BLOCK, Some(20_000)), None);
        // A minute later the channel does not get a minute's worth of data for free.
        let later = start + Duration::from_secs(60);
        let last = send_on_a_stopped_clock(&mut limiter, later, 10, Some(20_000));
        assert_eq!(last - later, Duration::from_micros(52_429 * 9));
    }

    #[test]
    fn removing_the_cap_forgets_the_debt() {
        let mut limiter = FileRateLimiter::default();
        let start = Instant::now();
        send_on_a_stopped_clock(&mut limiter, start, 3, Some(1_000));
        assert_eq!(limiter.charge(start, BLOCK, None), None);
        assert_eq!(limiter.charge(start, BLOCK, Some(1_000)), None);
    }
}
