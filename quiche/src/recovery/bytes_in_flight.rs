// Copyright (C) 2025, Cloudflare, Inc.
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

/// Estimate the total duration a connection has bytes-in-flight.
///
/// There can be multiple transitions from bytes-in-flight >0 to 0 and 0 to >0
/// during a connection's lifetime. Total bytes-in-flight duration is the sum of
/// all intervals that transition from idle to not-idle and back to idle. Close
/// intervals are the ones that transitioned back to idle. The open one is the
/// most recent interval for which we only have a start time, but no end time.
#[derive(Default)]
pub struct BytesInFlight {
    // Current bytes in flight.
    current: usize,

    // Instant at which bytes_in_flight transitioned from 0 to >0.
    // Set if bytes_in_flight is currently >0 which indicates that
    // the bytes in flight interval is currently "open".
    interval_start: Option<Instant>,

    // Duration of the current open interval.
    open_interval_duration: Duration,

    // Sum of closed interval durations seen so far.
    closed_interval_duration: Duration,
}

impl BytesInFlight {
    /// Add to bytes in flight.  Record the start time when
    /// `bytes_in_flight` was 0 at the beginning of the function.
    pub(crate) fn add(&mut self, delta: usize, now: Instant) {
        if delta == 0 {
            return;
        }

        self.current += delta;

        if self.interval_start.is_some() {
            self.update_in_flight_duration(now);
        } else {
            self.interval_start = Some(now);
        }
    }

    /// Substract from bytes in flight.  If `bytes_in_flight` drops to 0,
    /// end the current `bytes_in_flight` >0 interval.
    pub(crate) fn saturating_subtract(&mut self, delta: usize, now: Instant) {
        self.current = self.current.saturating_sub(delta);
        self.update_in_flight_duration(now);
    }

    /// Current bytes in flight.
    pub(crate) const fn get(&self) -> usize {
        self.current
    }

    /// Returns true if there are 0 bytes in flight.
    pub(crate) const fn is_zero(&self) -> bool {
        self.current == 0
    }

    /// Total time during which `bytes_in_flight` was > 0.
    pub(crate) const fn get_duration(&self) -> Duration {
        self.closed_interval_duration
            .saturating_add(self.open_interval_duration)
    }

    fn update_in_flight_duration(&mut self, now: Instant) {
        if let Some(start) = self.interval_start {
            // Event times can arrive out of order. Duration already observed
            // for an open interval must never decrease, and an observation
            // earlier than the interval start adds no elapsed time.
            let observed = self
                .open_interval_duration
                .max(now.saturating_duration_since(start));
            if self.current == 0 {
                self.open_interval_duration = Duration::ZERO;
                self.closed_interval_duration =
                    self.closed_interval_duration.saturating_add(observed);
                self.interval_start = None;
            } else {
                self.open_interval_duration = observed;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Multiple send, ACK and loss callbacks can pass non-monotonic event
    /// timestamps. The duration metric must never move backwards. Earlier
    /// timestamps must not erase elapsed time already observed.
    #[test]
    fn in_flight_duration_is_monotonic_under_out_of_order_timestamps() {
        let start = Instant::now();
        let mut in_flight = BytesInFlight::default();
        in_flight.add(3, start);

        in_flight.add(2, start + Duration::from_secs(10));
        assert_eq!(in_flight.get_duration(), Duration::from_secs(10));

        in_flight.add(1, start + Duration::from_secs(5));
        assert_eq!(in_flight.get_duration(), Duration::from_secs(10));
        in_flight.saturating_subtract(2, start + Duration::from_secs(7));
        assert_eq!(in_flight.get_duration(), Duration::from_secs(10));

        in_flight.saturating_subtract(4, start + Duration::from_secs(8));
        assert_eq!(in_flight.get_duration(), Duration::from_secs(10));
        assert!(in_flight.is_zero());

        // A second interval adds its own duration instead of altering the
        // previously closed interval, even with a backdated observation.
        let second_start = start + Duration::from_secs(20);
        in_flight.add(1, second_start);
        in_flight.saturating_subtract(1, second_start - Duration::from_secs(2));
        assert!(in_flight.is_zero());
        assert_eq!(in_flight.get_duration(), Duration::from_secs(10));
    }

    #[test]
    fn in_flight_duration_handles_updates_before_interval_start() {
        let start = Instant::now() + Duration::from_secs(5);
        let mut in_flight = BytesInFlight::default();
        in_flight.add(2, start);
        in_flight.add(1, start - Duration::from_secs(3));
        assert_eq!(in_flight.get_duration(), Duration::ZERO);

        in_flight.saturating_subtract(1, start - Duration::from_secs(1));
        assert_eq!(in_flight.get_duration(), Duration::ZERO);
        in_flight.saturating_subtract(2, start + Duration::from_secs(7));
        assert_eq!(in_flight.get_duration(), Duration::from_secs(7));
    }

    #[test]
    fn bytes_in_flight_basic() {
        let start = Instant::now();

        let mut bytes_in_flight: BytesInFlight = Default::default();
        assert_eq!(bytes_in_flight.get(), 0);
        assert_eq!(bytes_in_flight.get_duration(), Duration::ZERO);

        // interval_start is initialized when bytes > 0.
        bytes_in_flight.add(1, start);
        assert_eq!(bytes_in_flight.get(), 1);
        assert_eq!(bytes_in_flight.get_duration(), Duration::ZERO);

        // Advance time forward and verify that the inflight time for an open
        // interval.
        let mut now = start + Duration::from_secs(2);
        bytes_in_flight.add(2, now);
        bytes_in_flight.add(3, now);
        assert_eq!(bytes_in_flight.get(), 6);
        // Interval start does not change on adds
        assert_eq!(bytes_in_flight.get_duration(), Duration::from_secs(2));

        now += Duration::from_secs(5);
        bytes_in_flight.saturating_subtract(3, now);
        // Bytes > 0, interval remains open.
        assert_eq!(bytes_in_flight.get(), 3);
        assert_eq!(bytes_in_flight.get_duration(), Duration::from_secs(7));

        bytes_in_flight.saturating_subtract(3, now);
        // Bytes == 0, interval is closed.
        assert_eq!(bytes_in_flight.get(), 0);
        assert_eq!(bytes_in_flight.get_duration(), Duration::from_secs(7));

        // Open a second interval.
        now += Duration::from_secs(30);
        bytes_in_flight.add(10, now);
        assert_eq!(bytes_in_flight.get(), 10);
        assert_eq!(bytes_in_flight.get_duration(), Duration::from_secs(7));

        // Close the second interval.
        now += Duration::from_secs(5);
        bytes_in_flight.saturating_subtract(10, now);
        assert_eq!(bytes_in_flight.get(), 0);
        // The two in-flight intervals lasted seven and five seconds, for an
        // expected total of twelve seconds.
        assert_eq!(bytes_in_flight.get_duration(), Duration::from_secs(12));
    }

    #[test]
    fn bytes_in_flight_saturating_sub() {
        let start = Instant::now();

        let mut bytes_in_flight: BytesInFlight = Default::default();
        bytes_in_flight.add(10, start);
        assert_eq!(bytes_in_flight.get(), 10);

        bytes_in_flight.saturating_subtract(7, start + Duration::from_secs(3));
        assert_eq!(bytes_in_flight.get(), 3);
        assert_eq!(bytes_in_flight.get_duration(), Duration::from_secs(3));
        // Interval is still open.
        bytes_in_flight.saturating_subtract(1, start + Duration::from_secs(20));
        assert_eq!(bytes_in_flight.get(), 2);
        assert_eq!(bytes_in_flight.get_duration(), Duration::from_secs(20));

        bytes_in_flight.saturating_subtract(7, start + Duration::from_secs(25));
        assert_eq!(bytes_in_flight.get(), 0);
        // Interval is closed.
        assert_eq!(bytes_in_flight.get_duration(), Duration::from_secs(25));
    }
}
