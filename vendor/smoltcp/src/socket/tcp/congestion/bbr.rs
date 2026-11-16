use super::{Controller, RttEstimator};
use crate::time::Instant;

const DEFAULT_MSS: usize = 1024;
const INIT_CWND_SEGMENTS: usize = 10;
const MIN_CWND_SEGMENTS: usize = 4;
const RTO_CWND_SEGMENTS: usize = 2;

const MIN_RTT_FLOOR_US: u64 = 100;
const MIN_RTT_FILTER_US: i64 = 10_000_000;
const PROBE_RTT_DURATION_US: i64 = 200_000;

const BW_WINDOW_ROUNDS: usize = 10;
const STARTUP_FULL_BW_ROUNDS: u8 = 3;

const GAIN_UNIT: u64 = 4;
const GAIN_CYCLE_LEN: usize = 8;
/// BBRv1 8-phase gain cycle: [5/4, 3/4, 1, 1, 1, 1, 1, 1] scaled by 4.
const PACING_GAINS_NUM: [u64; GAIN_CYCLE_LEN] = [5, 3, 4, 4, 4, 4, 4, 4];

const TX_SAMPLE_CAP: usize = 16;

/// Operating state of the integer BBRv1 controller.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct TxSample {
    tx_end: u64,
    tx_time_us: i64,
    delivered_at_tx: u64,
    delivered_time_at_tx_us: i64,
}

/// Pure-Rust integer BBRv1 congestion controller (`u64`/`u128`/`usize`, no floating-point math).
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Bbr {
    mode: Mode,
    cwnd: usize,
    mss: usize,
    rwnd: usize,
    rwnd_seen: bool,
    saw_ack: bool,

    // Delivery and microsecond timing state (sub-ms loopback compatible).
    delivered: u64,
    delivered_time_us: Option<i64>,
    tx_seq_head: u64,
    expect_retransmit: bool,
    tx_samples: [TxSample; TX_SAMPLE_CAP],
    tx_head: usize,
    tx_len: usize,

    // Round tracking and 10-round windowed max bandwidth filter (bytes/sec).
    round_count: u64,
    next_round_delivered: u64,
    round_start_us: Option<i64>,
    round_delivered_start: u64,
    round_rwnd_limited: bool,
    bw_window: [u64; BW_WINDOW_ROUNDS],
    max_bw_bps: u64,

    // Minimum RTT tracking (microseconds, floored >= 100us).
    min_rtt_us: u64,
    min_rtt_stamp_us: i64,
    has_min_rtt: bool,

    // Startup exit detection (3 non-rwnd-limited rounds without >=25% growth).
    full_bw_bps: u64,
    full_bw_count: u8,
    full_bw_reached: bool,

    // ProbeBw cycle state.
    cycle_idx: usize,
    cycle_stamp_us: i64,
    cycle_start_round: u64,

    // ProbeRtt cycle state.
    probe_rtt_enter_us: i64,
    probe_rtt_done_us: Option<i64>,
    probe_rtt_min_us: u64,

    // Loss / fast recovery state.
    in_recovery: bool,
    prior_cwnd: usize,
    last_ack_us: Option<i64>,
}

impl Bbr {
    /// Construct a new BBRv1 controller initialized in `Startup`.
    pub fn new() -> Bbr {
        let init_cwnd = INIT_CWND_SEGMENTS * DEFAULT_MSS;
        Bbr {
            mode: Mode::Startup,
            cwnd: init_cwnd,
            mss: DEFAULT_MSS,
            rwnd: usize::MAX,
            rwnd_seen: false,
            saw_ack: false,

            delivered: 0,
            delivered_time_us: None,
            tx_seq_head: 0,
            expect_retransmit: false,
            tx_samples: [TxSample::default(); TX_SAMPLE_CAP],
            tx_head: 0,
            tx_len: 0,

            round_count: 0,
            next_round_delivered: 0,
            round_start_us: None,
            round_delivered_start: 0,
            round_rwnd_limited: false,
            bw_window: [0; BW_WINDOW_ROUNDS],
            max_bw_bps: 0,

            min_rtt_us: 0,
            min_rtt_stamp_us: 0,
            has_min_rtt: false,

            full_bw_bps: 0,
            full_bw_count: 0,
            full_bw_reached: false,

            cycle_idx: 0,
            cycle_stamp_us: 0,
            cycle_start_round: 0,

            probe_rtt_enter_us: 0,
            probe_rtt_done_us: None,
            probe_rtt_min_us: u64::MAX,

            in_recovery: false,
            prior_cwnd: init_cwnd,
            last_ack_us: None,
        }
    }

    #[cfg(test)]
    pub(super) fn mode(&self) -> Mode {
        self.mode
    }

    #[cfg(test)]
    pub(super) fn min_rtt_us(&self) -> u64 {
        self.min_rtt_us
    }

    pub(in crate::socket::tcp) fn max_bw_bps(&self) -> u64 {
        self.max_bw_bps
    }

    #[cfg(test)]
    pub(super) fn pacing_gain_num(&self) -> u64 {
        match self.mode {
            Mode::Startup => 11,
            Mode::Drain => 1,
            Mode::ProbeBw => PACING_GAINS_NUM[self.cycle_idx],
            Mode::ProbeRtt => GAIN_UNIT,
        }
    }

    #[inline]
    fn min_cwnd(&self) -> usize {
        MIN_CWND_SEGMENTS.saturating_mul(self.mss).max(1)
    }

    #[inline]
    fn rwnd_cap(&self) -> usize {
        self.rwnd.max(self.min_cwnd())
    }

    #[inline]
    fn push_tx_sample(&mut self, sample: TxSample) {
        if self.tx_len < TX_SAMPLE_CAP {
            let idx = (self.tx_head + self.tx_len) % TX_SAMPLE_CAP;
            self.tx_samples[idx] = sample;
            self.tx_len += 1;
        } else {
            // Preserve earlier samples from the start of the flight so the first
            // ACKs match immediately, coalescing the tail milestone in-place.
            let tail_idx = (self.tx_head + TX_SAMPLE_CAP - 1) % TX_SAMPLE_CAP;
            self.tx_samples[tail_idx].tx_end = sample.tx_end;
        }
    }

    #[inline]
    fn pop_matching_tx_sample(&mut self, delivered_now: u64) -> Option<TxSample> {
        let mut matched = None;
        while self.tx_len > 0 {
            let sample = self.tx_samples[self.tx_head];
            if sample.tx_end <= delivered_now {
                self.tx_head = (self.tx_head + 1) % TX_SAMPLE_CAP;
                self.tx_len -= 1;
                matched = Some(sample);
            } else {
                break;
            }
        }
        matched
    }

    fn record_bw_sample(&mut self, bw_bps: u64) {
        if bw_bps == 0 {
            return;
        }
        let slot = (self.round_count as usize) % BW_WINDOW_ROUNDS;
        if bw_bps > self.bw_window[slot] {
            self.bw_window[slot] = bw_bps;
        }
        let mut peak = 0u64;
        for &v in &self.bw_window {
            if v > peak {
                peak = v;
            }
        }
        self.max_bw_bps = peak;
    }

    fn advance_round(&mut self, now_us: i64) {
        let round_bytes = self.delivered.saturating_sub(self.round_delivered_start);
        let round_elapsed_us = self
            .round_start_us
            .map(|start| now_us.saturating_sub(start).max(0) as u64)
            .unwrap_or(0);

        if round_bytes > 0 && round_elapsed_us > 0 {
            let clamped_us = round_elapsed_us.max(self.min_rtt_us.max(MIN_RTT_FLOOR_US));
            let round_bw = ((round_bytes as u128).saturating_mul(1_000_000) / clamped_us as u128)
                .min(u64::MAX as u128) as u64;
            self.record_bw_sample(round_bw);
        }

        if self.mode == Mode::Startup && !self.full_bw_reached {
            if self.rwnd_seen && self.cwnd >= self.rwnd {
                self.round_rwnd_limited = true;
            }
            if !self.round_rwnd_limited && self.max_bw_bps > 0 {
                // Exit Startup only after 3 non-rwnd-limited rounds without >=25% bw gain.
                if (self.max_bw_bps as u128).saturating_mul(4)
                    >= (self.full_bw_bps as u128).saturating_mul(5)
                {
                    self.full_bw_bps = self.max_bw_bps;
                    self.full_bw_count = 0;
                } else {
                    self.full_bw_count = self.full_bw_count.saturating_add(1);
                    if self.full_bw_count >= STARTUP_FULL_BW_ROUNDS {
                        self.full_bw_reached = true;
                        self.mode = Mode::Drain;
                    }
                }
            }
        }

        self.round_count = self.round_count.saturating_add(1);
        let clear_slot = (self.round_count as usize) % BW_WINDOW_ROUNDS;
        self.bw_window[clear_slot] = 0;
        let mut peak = 0u64;
        for &v in &self.bw_window {
            if v > peak {
                peak = v;
            }
        }
        if !self.full_bw_reached {
            // Preserve the Startup high-water mark while rolling across clear slots.
            self.max_bw_bps = peak.max(self.full_bw_bps);
        } else if peak > 0 {
            // After Startup, follow the 10-round windowed peak so BW can decay.
            self.max_bw_bps = peak;
        }
        self.round_delivered_start = self.delivered;
        self.round_start_us = Some(now_us);
        self.round_rwnd_limited = self.rwnd_seen && self.cwnd >= self.rwnd;
    }

    fn bdp_bytes(&self) -> usize {
        if self.max_bw_bps == 0 || !self.has_min_rtt {
            return self.cwnd.max(self.min_cwnd());
        }
        let bdp = (self.max_bw_bps as u128)
            .saturating_mul(self.min_rtt_us.max(MIN_RTT_FLOOR_US) as u128)
            / 1_000_000;
        bdp.min(usize::MAX as u128) as usize
    }

    fn cwnd_gain_num(&self) -> u64 {
        match self.mode {
            Mode::Startup => 8,
            Mode::Drain => 4,
            Mode::ProbeBw => {
                let pacing = PACING_GAINS_NUM[self.cycle_idx];
                if pacing > GAIN_UNIT {
                    // 5/4 probing phase: 2.5x BDP headroom for GSO/GRO bursts.
                    10
                } else if pacing == GAIN_UNIT {
                    // Cruise phase: 2x BDP soft floor to match/beat Cubic on clean links.
                    8
                } else {
                    // 3/4 drain phase: drain standing queue down to 1x BDP without starving.
                    4
                }
            }
            Mode::ProbeRtt => 4,
        }
    }

    fn target_cwnd(&self) -> usize {
        let min_cwnd = self.min_cwnd();
        if self.mode == Mode::ProbeRtt {
            return min_cwnd.min(self.rwnd_cap());
        }
        if self.max_bw_bps == 0 || !self.has_min_rtt {
            return self.cwnd.max(min_cwnd).min(self.rwnd_cap());
        }
        let bdp = self.bdp_bytes() as u128;
        let gain = self.cwnd_gain_num() as u128;
        let mut target =
            ((bdp.saturating_mul(gain)) / GAIN_UNIT as u128).min(usize::MAX as u128) as usize;
        if matches!(self.mode, Mode::ProbeBw) && PACING_GAINS_NUM[self.cycle_idx] >= GAIN_UNIT {
            let floor_2bdp = (bdp.saturating_mul(2)).min(usize::MAX as u128) as usize;
            if target < floor_2bdp {
                target = floor_2bdp;
            }
        }
        target.max(min_cwnd).min(self.rwnd_cap())
    }

    fn update_min_rtt(&mut self, now_us: i64, rtt_us: u64, in_flight: usize) {
        let sample_us = rtt_us.max(MIN_RTT_FLOOR_US);
        let filter_expired =
            self.has_min_rtt && now_us.saturating_sub(self.min_rtt_stamp_us) > MIN_RTT_FILTER_US;

        if self.mode == Mode::ProbeRtt {
            if sample_us < self.probe_rtt_min_us {
                self.probe_rtt_min_us = sample_us;
            }
            if sample_us <= self.min_rtt_us {
                self.min_rtt_us = sample_us;
                self.min_rtt_stamp_us = now_us;
            }
            if self.probe_rtt_done_us.is_none()
                && (in_flight <= self.min_cwnd()
                    || now_us.saturating_sub(self.probe_rtt_enter_us)
                        >= self.min_rtt_us.max(MIN_RTT_FLOOR_US) as i64)
            {
                self.probe_rtt_done_us = Some(now_us.saturating_add(PROBE_RTT_DURATION_US));
            }
            let done_ready = self.probe_rtt_done_us.is_some_and(|done| now_us >= done);
            let hard_cap =
                now_us.saturating_sub(self.probe_rtt_enter_us) >= PROBE_RTT_DURATION_US * 2;
            if done_ready || hard_cap {
                if self.probe_rtt_min_us < u64::MAX {
                    self.min_rtt_us = self.probe_rtt_min_us.max(MIN_RTT_FLOOR_US);
                }
                self.min_rtt_stamp_us = now_us;
                self.probe_rtt_done_us = None;
                self.mode = if self.full_bw_reached {
                    Mode::ProbeBw
                } else {
                    Mode::Startup
                };
                if self.mode == Mode::ProbeBw {
                    self.cycle_stamp_us = now_us;
                    self.cycle_start_round = self.round_count;
                }
                let restored = self.prior_cwnd.max(self.target_cwnd());
                self.cwnd = restored.max(self.min_cwnd()).min(self.rwnd_cap());
            }
            return;
        }

        if !self.has_min_rtt || sample_us <= self.min_rtt_us {
            self.min_rtt_us = sample_us;
            self.min_rtt_stamp_us = now_us;
            self.has_min_rtt = true;
        } else if filter_expired && !self.in_recovery {
            // min_rtt was not refreshed within 10s: enter ProbeRtt for 200ms at 4 * mss.
            self.prior_cwnd = self.cwnd;
            self.mode = Mode::ProbeRtt;
            self.probe_rtt_enter_us = now_us;
            self.probe_rtt_done_us = if in_flight <= self.min_cwnd() {
                Some(now_us.saturating_add(PROBE_RTT_DURATION_US))
            } else {
                None
            };
            self.probe_rtt_min_us = sample_us;
            self.cwnd = self.min_cwnd().min(self.rwnd_cap());
        }
    }
}

impl Controller for Bbr {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_ack(&mut self, now: Instant, len: usize, in_flight: usize, rtt: &RttEstimator) {
        if len == 0 {
            return;
        }
        let now_us = now.total_micros();
        self.saw_ack = true;
        self.delivered = self.delivered.saturating_add(len as u64);

        let highest_expected = self.delivered.saturating_add(in_flight as u64);
        if highest_expected > self.tx_seq_head {
            self.tx_seq_head = highest_expected;
        }

        let matched = self.pop_matching_tx_sample(self.delivered);
        if in_flight == 0 {
            self.tx_seq_head = self.delivered;
            self.tx_head = 0;
            self.tx_len = 0;
        }

        let rtt_sample_us = if let Some(sample) = matched {
            let measured = now_us.saturating_sub(sample.tx_time_us).max(0) as u64;
            if measured > 0 {
                measured.max(MIN_RTT_FLOOR_US)
            } else if rtt.smoothed_rtt() > 0 {
                (rtt.smoothed_rtt() as u64).saturating_mul(1000)
            } else {
                MIN_RTT_FLOOR_US
            }
        } else if rtt.smoothed_rtt() > 0 {
            (rtt.smoothed_rtt() as u64).saturating_mul(1000)
        } else if self.has_min_rtt {
            self.min_rtt_us
        } else if let Some(prev) = self.last_ack_us {
            let delta = now_us.saturating_sub(prev).max(0) as u64;
            if delta > 0 {
                delta.max(MIN_RTT_FLOOR_US)
            } else {
                MIN_RTT_FLOOR_US
            }
        } else {
            MIN_RTT_FLOOR_US
        };

        // Update delivery-rate estimate from microsecond timestamps.
        if let Some(sample) = matched {
            let delivered_delta = self.delivered.saturating_sub(sample.delivered_at_tx);
            let ack_elapsed = now_us.saturating_sub(sample.delivered_time_at_tx_us).max(0) as u64;
            let send_elapsed = sample
                .tx_time_us
                .saturating_sub(self.round_start_us.unwrap_or(sample.tx_time_us))
                .max(0) as u64;
            let interval_us = ack_elapsed
                .max(send_elapsed)
                .max(rtt_sample_us)
                .max(MIN_RTT_FLOOR_US);
            if delivered_delta > 0 {
                let bw = ((delivered_delta as u128).saturating_mul(1_000_000) / interval_us as u128)
                    .min(u64::MAX as u128) as u64;
                self.record_bw_sample(bw);
            }
        } else {
            if self.round_start_us.is_none() {
                self.round_start_us = Some(self.last_ack_us.unwrap_or(now_us));
            }
            let prev_t = self.last_ack_us.unwrap_or(now_us);
            let dt = now_us.saturating_sub(prev_t).max(0) as u64;
            if dt > 0 {
                let bw = ((len as u128).saturating_mul(1_000_000)
                    / dt.max(MIN_RTT_FLOOR_US) as u128)
                    .min(u64::MAX as u128) as u64;
                self.record_bw_sample(bw);
            }
        }

        // Round boundary detection.
        let round_done = if let Some(sample) = matched {
            sample.delivered_at_tx >= self.next_round_delivered
        } else {
            let rtt_elapsed = self
                .round_start_us
                .is_some_and(|start| now_us.saturating_sub(start) >= rtt_sample_us as i64);
            self.delivered >= self.next_round_delivered && rtt_elapsed
        };
        if round_done {
            self.advance_round(now_us);
            self.next_round_delivered = self
                .delivered
                .saturating_add((in_flight as u64).max(self.mss as u64));
        }

        self.delivered_time_us = Some(now_us);
        self.last_ack_us = Some(now_us);

        self.update_min_rtt(now_us, rtt_sample_us, in_flight);

        if self.rwnd_seen && self.cwnd >= self.rwnd {
            self.round_rwnd_limited = true;
        }

        if self.mode == Mode::ProbeRtt {
            return;
        }

        if self.in_recovery {
            // Exit fast recovery on the first new ACK, restoring BDP-derived target cwnd.
            self.in_recovery = false;
            let restored = if self.mode == Mode::Startup {
                self.prior_cwnd.max(self.target_cwnd())
            } else {
                self.target_cwnd()
            };
            self.cwnd = restored.max(self.min_cwnd()).min(self.rwnd_cap());
            return;
        }

        match self.mode {
            Mode::Startup => {
                let grown = self.cwnd.saturating_add(len.saturating_mul(2));
                if self.rwnd_seen && grown >= self.rwnd {
                    self.round_rwnd_limited = true;
                }
                self.cwnd = grown.min(self.rwnd_cap()).max(self.min_cwnd());
            }
            Mode::Drain => {
                let bdp_target = self.target_cwnd();
                self.cwnd = bdp_target;
                if in_flight <= bdp_target {
                    self.mode = Mode::ProbeBw;
                    self.cycle_idx = 0;
                    self.cycle_stamp_us = now_us;
                    self.cycle_start_round = self.round_count;
                    self.cwnd = self.target_cwnd();
                }
            }
            Mode::ProbeBw => {
                let phase_dur = self.min_rtt_us.max(MIN_RTT_FLOOR_US) as i64;
                if now_us.saturating_sub(self.cycle_stamp_us) >= phase_dur
                    && self.round_count > self.cycle_start_round
                {
                    self.cycle_idx = (self.cycle_idx + 1) % GAIN_CYCLE_LEN;
                    self.cycle_stamp_us = now_us;
                    self.cycle_start_round = self.round_count;
                }
                let target = self.target_cwnd();
                if self.cwnd < target {
                    self.cwnd = self.cwnd.saturating_add(len).min(target);
                } else {
                    self.cwnd = target;
                }
            }
            Mode::ProbeRtt => {}
        }
    }

    fn on_dup_ack(&mut self, _now: Instant, _len: usize, _in_flight: usize) {
        if self.in_recovery && self.mode != Mode::ProbeRtt {
            let recovery_cwnd = self
                .target_cwnd()
                .saturating_mul(7)
                .checked_div(8)
                .unwrap_or(0)
                .max(self.min_cwnd());
            self.cwnd = recovery_cwnd.min(self.rwnd_cap());
        }
    }

    fn post_transmit(&mut self, now: Instant, len: usize) {
        if len == 0 {
            return;
        }
        let now_us = now.total_micros();
        if self.delivered_time_us.is_none() {
            self.delivered_time_us = Some(now_us);
        }
        if self.round_start_us.is_none() {
            self.round_start_us = Some(now_us);
        }
        if self.expect_retransmit {
            // Karn's rule: skip RTT/BW sampling on the retransmitted segment itself.
            self.expect_retransmit = false;
            return;
        }
        self.tx_seq_head = self.tx_seq_head.saturating_add(len as u64);
        let sample = TxSample {
            tx_end: self.tx_seq_head,
            tx_time_us: now_us,
            delivered_at_tx: self.delivered,
            delivered_time_at_tx_us: self.delivered_time_us.unwrap_or(now_us),
        };
        self.push_tx_sample(sample);
    }

    fn on_loss(&mut self, _now: Instant, _in_flight: usize) {
        // Keep max_bw and min_rtt intact across packet loss; fast recovery uses
        // (target_cwnd * 7 / 8).max(4 * mss) until the next new ACK arrives.
        self.expect_retransmit = true;
        if self.in_recovery || self.mode == Mode::ProbeRtt {
            return;
        }
        self.prior_cwnd = self.cwnd;
        self.in_recovery = true;
        let base_target = self.target_cwnd().max(self.cwnd);
        let recovery_cwnd = (base_target.saturating_mul(7) / 8).max(self.min_cwnd());
        self.cwnd = recovery_cwnd.min(self.rwnd_cap());
    }

    fn on_rto(&mut self, _now: Instant, _in_flight: usize) {
        // Genuine RTO timeout drops cwnd to 2 * mss.
        self.expect_retransmit = true;
        self.in_recovery = false;
        self.prior_cwnd = self.cwnd;
        self.cwnd = RTO_CWND_SEGMENTS
            .saturating_mul(self.mss)
            .max(1)
            .min(self.rwnd_cap());
    }

    fn set_mss(&mut self, mss: usize) {
        let new_mss = mss.max(1);
        let old_mss = self.mss;
        self.mss = new_mss;
        if !self.saw_ack && self.cwnd == INIT_CWND_SEGMENTS * old_mss {
            self.cwnd = INIT_CWND_SEGMENTS.saturating_mul(new_mss);
            self.prior_cwnd = self.cwnd;
        } else if self.cwnd > self.min_cwnd() {
            self.cwnd = self.cwnd.max(self.min_cwnd());
        }
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        self.rwnd = remote_window;
        self.rwnd_seen = true;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::socket::tcp::congestion::cubic::Cubic;

    fn rtte_ms(ms: u32) -> RttEstimator {
        let mut r = RttEstimator::default();
        r.sample(ms);
        r
    }

    #[test]
    fn sub_ms_loopback_tracks_microsecond_rtt_and_floors_at_100us() {
        let mut bbr = Bbr::new();
        bbr.set_mss(1460);
        let rtte_zero_ms = rtte_ms(0);

        // 500us loopback RTT (rtte.smoothed_rtt() == 0 ms)
        bbr.post_transmit(Instant::from_micros(0), 1460);
        bbr.on_ack(Instant::from_micros(500), 1460, 0, &rtte_zero_ms);
        assert_eq!(bbr.min_rtt_us(), 500);
        assert!(bbr.max_bw_bps() > 0);

        // Zero-delta synthetic loopback must clamp min_rtt_us >= 100
        let mut bbr_zero = Bbr::new();
        bbr_zero.set_mss(1460);
        bbr_zero.post_transmit(Instant::from_micros(1000), 1460);
        bbr_zero.on_ack(Instant::from_micros(1000), 1460, 0, &rtte_zero_ms);
        assert!(bbr_zero.min_rtt_us() >= 100);
    }

    #[test]
    fn startup_grows_with_2x_len_and_waits_through_rwnd_limit() {
        let mut bbr = Bbr::new();
        bbr.set_mss(1000);
        bbr.set_remote_window(12_000); // Small initial rwnd
        let rtte = rtte_ms(40);

        let before = bbr.window();
        bbr.post_transmit(Instant::from_millis(0), 1000);
        bbr.on_ack(Instant::from_millis(40), 1000, 5000, &rtte);
        // Capped at rwnd=12_000 (10_000 + 2*1000 == 12_000)
        assert_eq!(bbr.window(), (before + 2000).min(12_000));

        // 6 full rounds capped at rwnd must NOT exit Startup.
        for round in 1..=6 {
            let t_tx = Instant::from_millis(round * 40);
            for _ in 0..12 {
                bbr.post_transmit(t_tx, 1000);
            }
            let t_ack = Instant::from_millis((round + 1) * 40);
            for left in (0..12).rev() {
                bbr.on_ack(t_ack, 1000, left * 1000, &rtte);
            }
            assert_eq!(bbr.mode(), Mode::Startup);
        }

        // Autotuning opens rwnd -> cwnd immediately expands again!
        bbr.set_remote_window(200_000);
        bbr.post_transmit(Instant::from_millis(320), 1000);
        bbr.on_ack(Instant::from_millis(360), 1000, 10_000, &rtte);
        assert!(bbr.window() > 12_000);
        assert_eq!(bbr.mode(), Mode::Startup);
    }

    #[test]
    fn startup_drain_probe_bw_8_cycle_and_probe_rtt() {
        let mut bbr = Bbr::new();
        bbr.set_mss(1000);
        bbr.set_remote_window(2_000_000);
        let rtte = rtte_ms(20);

        // Simulate constant bottleneck bandwidth across rounds until Startup -> Drain -> ProbeBw.
        let mut t_ms = 0i64;
        let mut entered_drain = false;
        let mut entered_probe_bw = false;
        for _ in 0..20 {
            let segs = 10usize;
            for _ in 0..segs {
                bbr.post_transmit(Instant::from_millis(t_ms), 1000);
            }
            t_ms += 20;
            for rem in (0..segs).rev() {
                bbr.on_ack(Instant::from_millis(t_ms), 1000, rem * 1000, &rtte);
                if bbr.mode() == Mode::Drain {
                    entered_drain = true;
                }
                if bbr.mode() == Mode::ProbeBw {
                    entered_probe_bw = true;
                }
            }
            if entered_probe_bw {
                break;
            }
        }
        assert!(entered_drain || entered_probe_bw);
        assert_eq!(bbr.mode(), Mode::ProbeBw);

        // Verify all 8 ProbeBw gains [5/4, 3/4, 1, 1, 1, 1, 1, 1].
        let mut observed = [0u64; 8];
        for slot in &mut observed {
            *slot = bbr.pacing_gain_num();
            for _ in 0..10 {
                bbr.post_transmit(Instant::from_millis(t_ms), 1000);
            }
            t_ms += 20;
            for rem in (0..10).rev() {
                bbr.on_ack(Instant::from_millis(t_ms), 1000, rem * 1000, &rtte);
            }
        }
        assert!(observed.contains(&5));
        assert!(observed.contains(&3));
        assert!(observed.contains(&4));

        // ProbeRtt does NOT trigger if min_rtt keeps refreshing within 10s.
        for _ in 0..60 {
            t_ms += 200;
            bbr.post_transmit(Instant::from_millis(t_ms), 1000);
            bbr.on_ack(Instant::from_millis(t_ms + 20), 1000, 0, &rtte);
            assert_ne!(bbr.mode(), Mode::ProbeRtt);
        }

        // When RTT inflates (20ms -> 50ms) and min_rtt is NOT refreshed for >10s, ProbeRtt activates for 200ms with 4 * mss.
        let rtte_inflated = rtte_ms(50);
        let jump_ms = t_ms + 11_000;
        bbr.post_transmit(Instant::from_millis(jump_ms), 1000);
        bbr.on_ack(
            Instant::from_millis(jump_ms + 50),
            1000,
            5000,
            &rtte_inflated,
        );
        assert_eq!(bbr.mode(), Mode::ProbeRtt);
        assert_eq!(bbr.window(), 4000);

        // After 200ms in ProbeRtt, exits back to ProbeBw.
        bbr.post_transmit(Instant::from_millis(jump_ms + 300), 1000);
        bbr.on_ack(Instant::from_millis(jump_ms + 350), 1000, 0, &rtte_inflated);
        assert_eq!(bbr.mode(), Mode::ProbeBw);
    }

    #[test]
    fn loss_keeps_max_bw_and_restores_cwnd_faster_than_cubic() {
        let mut bbr = Bbr::new();
        let mut cubic = Cubic::new();
        bbr.set_mss(1000);
        cubic.set_mss(1000);
        bbr.set_remote_window(1_000_000);
        cubic.set_remote_window(1_000_000);
        let rtte = rtte_ms(40);

        // Warm up both over several 40ms rounds with 20KB/RTT (500 KB/s).
        let mut t_ms = 0i64;
        for _ in 0..8 {
            for _ in 0..20 {
                bbr.post_transmit(Instant::from_millis(t_ms), 1000);
                cubic.post_transmit(Instant::from_millis(t_ms), 1000);
            }
            t_ms += 40;
            for rem in (0..20).rev() {
                bbr.on_ack(Instant::from_millis(t_ms), 1000, rem * 1000, &rtte);
                cubic.on_ack(Instant::from_millis(t_ms), 1000, rem * 1000, &rtte);
            }
        }
        let bw_before_loss = bbr.max_bw_bps();
        assert!(bw_before_loss > 0);

        // 3 dupACK fast retransmit loss event.
        bbr.on_loss(Instant::from_millis(t_ms), 20_000);
        cubic.on_loss(Instant::from_millis(t_ms), 20_000);
        assert_eq!(bbr.max_bw_bps(), bw_before_loss);
        assert!(bbr.window() >= 4000);

        // First new ACK restores BBR target_cwnd from max_bw * min_rtt, far above Cubic's 0.7x cut.
        t_ms += 40;
        bbr.post_transmit(Instant::from_millis(t_ms - 40), 1000);
        cubic.post_transmit(Instant::from_millis(t_ms - 40), 1000);
        bbr.on_ack(Instant::from_millis(t_ms), 1000, 10_000, &rtte);
        cubic.on_ack(Instant::from_millis(t_ms), 1000, 10_000, &rtte);
        assert!(bbr.window() >= cubic.window());

        // Real RTO drops to 2 * mss.
        bbr.on_rto(Instant::from_millis(t_ms + 200), 10_000);
        assert_eq!(bbr.window(), 2000);
    }

    #[test]
    fn max_bw_decays_after_startup_when_bandwidth_drops() {
        let mut bbr = Bbr::new();
        bbr.set_mss(1000);
        bbr.set_remote_window(1_000_000);
        let rtte = rtte_ms(40);

        // Drive Startup at a high burst (~1 MB/s: 40 KB per 40 ms round) until it exits Startup.
        let mut t_ms = 0i64;
        for _ in 0..8 {
            for _ in 0..40 {
                bbr.post_transmit(Instant::from_millis(t_ms), 1000);
            }
            t_ms += 40;
            for rem in (0..40).rev() {
                bbr.on_ack(Instant::from_millis(t_ms), 1000, rem * 1000, &rtte);
            }
            if bbr.mode() != Mode::Startup {
                break;
            }
        }
        assert_ne!(bbr.mode(), Mode::Startup, "must exit Startup on plateau");
        let peak_startup_bw = bbr.max_bw_bps();
        assert!(peak_startup_bw >= 800_000);

        // Narrow bottleneck to 200 KB/s (8 KB per 40 ms round) for > BW_WINDOW_ROUNDS rounds.
        for _ in 0..(BW_WINDOW_ROUNDS + 3) {
            for _ in 0..8 {
                bbr.post_transmit(Instant::from_millis(t_ms), 1000);
            }
            t_ms += 40;
            for rem in (0..8).rev() {
                bbr.on_ack(Instant::from_millis(t_ms), 1000, rem * 1000, &rtte);
            }
        }

        let decayed_bw = bbr.max_bw_bps();
        assert!(
            decayed_bw <= peak_startup_bw / 2,
            "expected max_bw_bps to decay after Startup from {peak_startup_bw}, got {decayed_bw}"
        );
        assert!(decayed_bw >= 150_000 && decayed_bw <= 300_000);
    }
}
