// Copyright (C) 2021, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::time::Duration;
use std::time::Instant;

use octets::MAX_VAR_INT;

// When autotuning the receiver window, decide how much
// we increase the window.
const WINDOW_INCREASE_FACTOR: u64 = 2;

// When autotuning the receiver window, check if the last
// update is within RTT * this constant.
const WINDOW_TRIGGER_FACTOR: u32 = 2;

#[derive(Default, Debug)]
pub struct FlowControl {
    /// Total consumed bytes by the receiver.
    consumed: u64,

    /// Flow control limit.
    max_data: u64,

    /// The receive window. This value is used for updating
    /// flow control limit.
    window: u64,

    /// The maximum receive window.
    max_window: u64,

    /// Last update time of `max_data` for autotuning the window.
    last_update: Option<Instant>,
}

impl FlowControl {
    pub fn new(max_data: u64, window: u64, max_window: u64) -> Self {
        let max_window = max_window.min(MAX_VAR_INT);
        Self {
            max_data: max_data.min(MAX_VAR_INT),
            window: window.min(max_window),
            max_window,
            ..Self::default()
        }
    }

    /// Returns the current window size.
    pub const fn window(&self) -> u64 {
        self.window
    }

    /// Returns the current flow limit.
    pub const fn max_data(&self) -> u64 {
        self.max_data
    }

    /// Returns the consumed bytes by the receiver.
    #[cfg(test)]
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Adds consumed bytes, saturating if the cumulative counter reaches
    /// `u64::MAX` rather than wrapping or panicking.
    pub const fn add_consumed(&mut self, consumed: u64) {
        self.consumed = self.consumed.saturating_add(consumed);
    }

    /// Returns true if the flow control needs to update `max_data`.
    ///
    /// This happens when the available window is smaller than the half
    /// of the current window.
    pub fn should_update_max_data(&self) -> bool {
        let available_window = self.max_data.saturating_sub(self.consumed);

        // For odd windows (including a one-byte window), rounding half up
        // makes exhausted credit trigger an update instead of stalling.
        available_window < self.window.div_ceil(2) &&
            self.max_data_next() > self.max_data
    }

    /// Returns the next flow-control limit. Credit is monotonic and always
    /// representable by the MAX_DATA and MAX_STREAM_DATA wire fields.
    pub fn max_data_next(&self) -> u64 {
        self.consumed
            .saturating_add(self.window)
            .min(MAX_VAR_INT)
            .max(self.max_data)
    }

    /// Commits the new `max_data` limit.
    pub fn update_max_data(&mut self, now: Instant) {
        self.max_data = self.max_data_next();
        self.last_update = Some(now);
    }

    /// Autotune the window size. When there is an another update
    /// within RTT x 2, bump the window x 2, capped by
    /// `max_window`.
    pub fn autotune_window(&mut self, now: Instant, rtt: Duration) {
        if let Some(elapsed) = self
            .last_update
            .and_then(|last| now.checked_duration_since(last))
        {
            if elapsed < rtt.saturating_mul(WINDOW_TRIGGER_FACTOR) {
                self.set_window(
                    self.window.saturating_mul(WINDOW_INCREASE_FACTOR),
                );
            }
        }
    }

    fn set_window(&mut self, window: u64) {
        self.window = std::cmp::min(window, self.max_window);
    }

    /// Increase the window to at least the requested lower bound, subject to
    /// the configured maximum.
    pub fn ensure_window_lower_bound(&mut self, min_window: u64) {
        if min_window > self.window {
            // ... we still need to clamp to `max_window`
            self.set_window(min_window);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_window_in_new() {
        let fc = FlowControl::new(100, 100, 50);
        assert_eq!(fc.max_data(), 100);
        assert_eq!(fc.window, 50);
    }

    #[test]
    fn initial_credit_and_window_are_wire_representable() {
        let fc = FlowControl::new(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(fc.max_data(), MAX_VAR_INT);
        assert_eq!(fc.window(), MAX_VAR_INT);
        assert_eq!(fc.max_data_next(), MAX_VAR_INT);
        assert!(!fc.should_update_max_data());
    }

    #[test]
    fn max_data() {
        let fc = FlowControl::new(100, 20, 100);

        assert_eq!(fc.max_data(), 100);
    }

    #[test]
    fn should_update_max_data() {
        let mut fc = FlowControl::new(100, 20, 100);

        fc.add_consumed(85);
        assert!(!fc.should_update_max_data());

        fc.add_consumed(10);
        assert!(fc.should_update_max_data());
    }

    #[test]
    fn max_data_next() {
        let mut fc = FlowControl::new(100, 20, 100);

        let consumed = 95;

        fc.add_consumed(consumed);
        assert!(fc.should_update_max_data());
        assert_eq!(fc.max_data_next(), consumed + 20);
    }

    #[test]
    fn update_max_data() {
        let mut fc = FlowControl::new(100, 20, 100);

        let consumed = 95;

        fc.add_consumed(consumed);
        assert!(fc.should_update_max_data());

        let max_data_next = fc.max_data_next();
        assert_eq!(fc.max_data_next(), consumed + 20);

        fc.update_max_data(Instant::now());
        assert_eq!(fc.max_data(), max_data_next);
    }

    #[test]
    fn autotune_window() {
        let w = 20;
        let mut fc = FlowControl::new(100, w, 100);

        let consumed = 95;

        fc.add_consumed(consumed);
        assert!(fc.should_update_max_data());

        let max_data_next = fc.max_data_next();
        assert_eq!(max_data_next, consumed + w);

        fc.update_max_data(Instant::now());
        assert_eq!(fc.max_data(), max_data_next);

        // Window size should be doubled.
        fc.autotune_window(Instant::now(), Duration::from_millis(100));

        let w = w * 2;
        let consumed_inc = 15;

        fc.add_consumed(consumed_inc);
        assert!(fc.should_update_max_data());

        let max_data_next = fc.max_data_next();
        assert_eq!(max_data_next, consumed + consumed_inc + w);
    }

    #[test]
    fn exhausted_small_windows_trigger_credit_update() {
        let mut one = FlowControl::new(1, 1, 1);
        assert!(!one.should_update_max_data());
        one.add_consumed(1);
        assert!(one.should_update_max_data());
        assert_eq!(one.max_data_next(), 2);

        let mut odd = FlowControl::new(5, 3, 3);
        odd.add_consumed(4);
        assert!(odd.should_update_max_data());
        odd.update_max_data(Instant::now());
        assert_eq!(odd.max_data(), 7);
    }

    #[test]
    fn flow_control_counters_saturate_and_limits_never_decrease() {
        let mut fc = FlowControl::new(MAX_VAR_INT - 4, 8, u64::MAX);
        assert_eq!(fc.max_data_next(), MAX_VAR_INT - 4);
        fc.update_max_data(Instant::now());
        assert_eq!(fc.max_data(), MAX_VAR_INT - 4);
        fc.add_consumed(MAX_VAR_INT - 2);
        assert!(fc.should_update_max_data());
        assert_eq!(fc.max_data_next(), MAX_VAR_INT);
        fc.update_max_data(Instant::now());
        assert_eq!(fc.max_data(), MAX_VAR_INT);
        fc.add_consumed(u64::MAX);
        assert_eq!(fc.consumed(), u64::MAX);
        assert_eq!(fc.max_data_next(), MAX_VAR_INT);
        // No new flow-control credit is possible at the wire limit.
        assert!(!fc.should_update_max_data());

        let mut overconsumed = FlowControl::new(5, 2, 4);
        overconsumed.add_consumed(6);
        assert!(overconsumed.should_update_max_data());
        assert_eq!(overconsumed.max_data_next(), 8);
        overconsumed.update_max_data(Instant::now());
        assert_eq!(overconsumed.max_data(), 8);
    }

    #[test]
    fn autotune_handles_large_windows_rtts_and_out_of_order_instants() {
        let base = Instant::now();
        let mut large = FlowControl::new(0, u64::MAX - 1, u64::MAX);
        large.update_max_data(base);
        large.autotune_window(base + Duration::from_millis(1), Duration::MAX);
        assert_eq!(large.window(), MAX_VAR_INT);
        assert_eq!(large.max_data_next(), MAX_VAR_INT);

        let mut out_of_order = FlowControl::new(100, 10, 100);
        out_of_order.update_max_data(base + Duration::from_secs(10));
        out_of_order.autotune_window(base, Duration::from_secs(1));
        assert_eq!(out_of_order.window(), 10);
        out_of_order.autotune_window(
            base + Duration::from_secs(11),
            Duration::from_secs(1),
        );
        assert_eq!(out_of_order.window(), 20);
    }

    #[test]
    fn ensure_window_lower_bound() {
        let w = 20;
        let mut fc = FlowControl::new(100, w, 100);

        // Window doesn't change.
        fc.ensure_window_lower_bound(w);
        assert_eq!(fc.window(), 20);

        // Window changed to the new value.
        fc.ensure_window_lower_bound(w * 2);
        assert_eq!(fc.window(), 40);

        // Window clamped to max_window
        fc.ensure_window_lower_bound(101);
        assert_eq!(fc.window(), 100);
    }
}
