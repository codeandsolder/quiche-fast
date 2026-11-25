// Copyright (C) 2026, Cloudflare, Inc.
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

use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use crate::datastore::StreamAccess;

/// A stream tracker rejected an unrepresentable value without mutating its
/// history, per-stream maxima or cumulative totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerError {
    /// The end position of a stream buffer access exceeds `u64::MAX`.
    StreamEndOverflow {
        stream_id: u64,
        offset: u64,
        length: u64,
    },
    /// The total of all stream maxima exceeds `u64::MAX`.
    RunningSumOverflow {
        stream_id: u64,
        total: u64,
        increment: u64,
    },
}

impl std::fmt::Display for TrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StreamEndOverflow { stream_id, offset, length } =>
                write!(f, "stream {stream_id} end offset overflows: {offset} + {length}"),
            Self::RunningSumOverflow { stream_id, total, increment } =>
                write!(f, "stream {stream_id} cumulative tracker total overflows: {total} + {increment}"),
        }
    }
}

impl std::error::Error for TrackerError {}

/// Per-stream histories with monotonic observed maxima and a checked aggregate.
///
/// A zero-valued observation is recorded even though it does not increase the
/// aggregate. A known initial limit is stored separately from observations
/// and contributes only once a stream is observed.
#[derive(Debug)]
pub struct StreamTracker<T> {
    streams: BTreeMap<u64, StreamHistory<T>>,
    sum_series: Vec<(f64, u64)>,
    running_sum: u64,
}

/// History and greatest observed position of one stream.
#[derive(Debug)]
pub struct StreamHistory<T> {
    points: Vec<(f64, T)>,
    initial: Option<u64>,
    maximum: u64,
}

impl<T> StreamHistory<T> {
    #[must_use = "the points are the recorded observations"]
    pub const fn points(&self) -> &[(f64, T)] {
        self.points.as_slice()
    }

    /// The advertised initial limit, if known. Not a recorded frame.
    #[must_use = "the result distinguishes a known initial limit from an unknown one"]
    pub const fn initial(&self) -> Option<u64> {
        self.initial
    }

    #[must_use = "the maximum is the greatest observed position"]
    pub const fn maximum(&self) -> u64 {
        self.maximum
    }
}

pub type StreamMaxTracker = StreamTracker<u64>;
pub type StreamBufferTracker = StreamTracker<StreamAccess>;

/// Observed QUIC STREAM or `RESET_STREAM` evidence. Optional fields in
/// qlog are retained as unknown rather than replaced by zero-valued samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicStreamObservation {
    Frame {
        offset: Option<u64>,
        length: Option<u64>,
        fin: Option<bool>,
    },
    Reset {
        final_size: u64,
    },
}

impl QuicStreamObservation {
    /// An exact STREAM endpoint can be plotted only when both fields are
    /// available. RESETs and incomplete records are not STREAM samples.
    #[must_use = "the result is a known STREAM endpoint, not an inferred value"]
    pub const fn frame_end(self) -> Option<u64> {
        match self {
            Self::Frame {
                offset: Some(offset),
                length: Some(length),
                ..
            } => offset.checked_add(length),
            _ => None,
        }
    }
}

/// An observation that provides a checked lower bound on a stream position.
pub trait StreamExtent {
    /// Return the stream position represented by the observation.
    ///
    /// # Errors
    /// Returns an error if the position cannot be represented.
    fn extent(&self, stream_id: u64) -> Result<u64, TrackerError>;
}

impl StreamExtent for u64 {
    fn extent(&self, _stream_id: u64) -> Result<u64, TrackerError> {
        Ok(*self)
    }
}

impl StreamExtent for StreamAccess {
    fn extent(&self, stream_id: u64) -> Result<u64, TrackerError> {
        self.offset.checked_add(self.length).ok_or(
            TrackerError::StreamEndOverflow {
                stream_id,
                offset: self.offset,
                length: self.length,
            },
        )
    }
}

impl StreamExtent for QuicStreamObservation {
    fn extent(&self, stream_id: u64) -> Result<u64, TrackerError> {
        match *self {
            Self::Frame { offset, length, .. } => {
                let offset = offset.unwrap_or_default();
                let length = length.unwrap_or_default();
                offset.checked_add(length).ok_or(
                    TrackerError::StreamEndOverflow {
                        stream_id,
                        offset,
                        length,
                    },
                )
            },
            Self::Reset { final_size } => Ok(final_size),
        }
    }
}

/// Track QUIC connection credit consumed by observed stream offsets.
///
/// Counts each stream's largest observed end offset, including holes and
/// `RESET_STREAM` final sizes, not packet payload lengths. Incomplete trace
/// metadata gives a lower bound.
pub type QuicStreamTracker = StreamTracker<QuicStreamObservation>;

impl QuicStreamTracker {
    /// Record stream evidence and advance the aggregate high-water mark.
    ///
    /// # Errors
    /// Returns an error before changing state if the observed endpoint or
    /// aggregate cannot be represented.
    pub fn observe(
        &mut self, stream_id: u64, observation: QuicStreamObservation, time: f64,
    ) -> Result<(), TrackerError> {
        let end = observation.extent(stream_id)?;
        self.record(stream_id, time, observation, end, None)?;
        Ok(())
    }
}

impl<T: StreamExtent> StreamTracker<T> {
    /// Reconstruct the aggregate in timestamp order when the input log is
    /// out of order. Sorting the ingestion-order totals is incorrect.
    /// Known initial limits are applied at the earliest actual observation
    /// of that stream, not counted for streams that have not been seen.
    ///
    /// # Errors
    /// Returns an error if an endpoint or aggregate cannot be represented.
    pub fn chronological_sum_series(
        &self,
    ) -> Result<Cow<'_, [(f64, u64)]>, TrackerError> {
        if self
            .sum_series
            .windows(2)
            .all(|pair| pair[0].0.total_cmp(&pair[1].0).is_le())
        {
            return Ok(Cow::Borrowed(&self.sum_series));
        }
        Ok(Cow::Owned(
            self.replay_series(|_, history| history.initial)?,
        ))
    }

    fn replay_series(
        &self, initial: impl Fn(u64, &StreamHistory<T>) -> Option<u64>,
    ) -> Result<Vec<(f64, u64)>, TrackerError> {
        let mut events = Vec::with_capacity(self.sum_series.len());
        for (&id, history) in &self.streams {
            events.extend(history.points.iter().map(|(time, observation)| {
                (*time, id, observation, initial(id, history))
            }));
        }
        events.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut maxima = BTreeMap::<u64, u64>::new();
        let mut total = 0_u64;
        let mut series = Vec::with_capacity(events.len());
        for (time, id, observation, initial) in events {
            let end = observation.extent(id)?.max(initial.unwrap_or_default());
            let previous = maxima.entry(id).or_default();
            let (maximum, sum) = checked_maximum(id, *previous, end, total)?;
            *previous = maximum;
            total = sum;
            series.push((time, total));
        }
        Ok(series)
    }
}

fn checked_maximum(
    stream_id: u64, old_max: u64, observed_max: u64, running_sum: u64,
) -> Result<(u64, u64), TrackerError> {
    let new_max = old_max.max(observed_max);
    let increment = new_max - old_max;
    let total = running_sum.checked_add(increment).ok_or(
        TrackerError::RunningSumOverflow {
            stream_id,
            total: running_sum,
            increment,
        },
    )?;
    Ok((new_max, total))
}

impl<T> Default for StreamTracker<T> {
    fn default() -> Self {
        Self {
            streams: BTreeMap::new(),
            sum_series: Vec::new(),
            running_sum: 0,
        }
    }
}

impl<T> StreamTracker<T> {
    #[must_use = "the map contains every observed stream"]
    pub const fn streams(&self) -> &BTreeMap<u64, StreamHistory<T>> {
        &self.streams
    }

    #[must_use = "the cached series reflects observations in their current replay order"]
    pub const fn sum_series(&self) -> &[(f64, u64)] {
        self.sum_series.as_slice()
    }

    #[must_use = "an absent stream has no observed maximum"]
    pub fn get_stream_max(&self, stream_id: u64) -> Option<u64> {
        self.streams.get(&stream_id).map(StreamHistory::maximum)
    }

    #[must_use = "the sum is the total of the per-stream maxima"]
    pub const fn current_sum(&self) -> u64 {
        self.running_sum
    }

    /// Validate all arithmetic before changing either history or aggregate.
    fn record(
        &mut self, stream_id: u64, time: f64, value: T, observed_max: u64,
        initial: Option<u64>,
    ) -> Result<Option<(u64, u64)>, TrackerError> {
        let entry = self.streams.entry(stream_id);
        let old_max = match &entry {
            Entry::Occupied(entry) => entry.get().maximum,
            Entry::Vacant(_) => 0,
        };
        let (new_max, total) =
            checked_maximum(stream_id, old_max, observed_max, self.running_sum)?;
        let increment = new_max - old_max;

        let history = entry.or_insert_with(|| StreamHistory {
            points: Vec::new(),
            initial,
            maximum: 0,
        });
        history.points.push((time, value));
        history.maximum = new_max;
        self.running_sum = total;
        self.sum_series.push((time, total));

        Ok((increment != 0).then_some((old_max, new_max)))
    }
}

impl StreamMaxTracker {
    /// Backfill previously unknown initial limits on already observed streams.
    ///
    /// Existing initial limits and raw frame history are unchanged. Rebuild
    /// the cached chronological total only when metadata has been added.
    ///
    /// # Errors
    /// Returns an aggregate overflow error without changing the tracker.
    pub fn hydrate_initial_limits(
        &mut self, limit_for_stream: impl Fn(u64) -> Option<u64>,
    ) -> Result<(), TrackerError> {
        let mut updates = BTreeMap::new();
        let mut total = self.running_sum;
        for (&id, history) in &self.streams {
            if history.initial.is_none() {
                if let Some(initial) = limit_for_stream(id) {
                    let (maximum, sum) =
                        checked_maximum(id, history.maximum, initial, total)?;
                    updates.insert(id, (initial, maximum));
                    total = sum;
                }
            }
        }
        if updates.is_empty() {
            return Ok(());
        }
        let series = self.replay_series(|id, history| {
            updates
                .get(&id)
                .map(|&(initial, _)| initial)
                .or(history.initial)
        })?;
        for (id, (initial, maximum)) in updates {
            if let Some(history) = self.streams.get_mut(&id) {
                history.initial = Some(initial);
                history.maximum = maximum;
            }
        }
        self.running_sum = total;
        self.sum_series = series;
        Ok(())
    }

    /// Record a flow-control maximum and the known initial limit for a new
    /// stream.
    ///
    /// # Errors
    /// Returns an error if the sum of observed stream maxima overflows.
    pub fn update(
        &mut self, stream_id: u64, new_value: u64, time: f64,
        initial: Option<u64>,
    ) -> Result<Option<(u64, u64)>, TrackerError> {
        let initial = if self.streams.contains_key(&stream_id) {
            None
        } else {
            initial
        };
        self.record(
            stream_id,
            time,
            new_value,
            new_value.max(initial.unwrap_or_default()),
            initial,
        )
    }
}

impl StreamBufferTracker {
    /// Record a buffer access and track the greatest observed end offset.
    ///
    /// # Errors
    /// Returns an error if the endpoint or sum of stream maxima overflows.
    pub fn update(
        &mut self, stream_id: u64, access: StreamAccess, time: f64,
    ) -> Result<Option<(u64, u64)>, TrackerError> {
        let end = access.extent(stream_id)?;
        self.record(stream_id, time, access, end, None)
    }
}

#[cfg(test)]
mod tests {
    use super::StreamBufferTracker;
    use super::StreamMaxTracker;
    use super::TrackerError;
    use crate::datastore::StreamAccess;

    type Update = (u64, u64, f64, Option<(u64, u64)>, u64);

    // Both public tracker variants must implement the same aggregate semantics.
    // Compare every intermediate maximum and total, including repeated and
    // out-of-order samples and interleaved streams.
    fn check_updates(updates: &[Update]) -> Result<(), TrackerError> {
        let mut maxima = StreamMaxTracker::default();
        let mut buffers = StreamBufferTracker::default();
        assert_eq!(maxima.current_sum(), 0);
        assert_eq!(buffers.current_sum(), 0);
        assert_eq!(maxima.get_stream_max(0), None);
        assert_eq!(buffers.get_stream_max(0), None);
        assert!(maxima.streams().is_empty());
        assert!(buffers.streams().is_empty());
        let mut expected_history = Vec::new();
        for &(stream, value, time, change, total) in updates {
            assert_eq!(maxima.update(stream, value, time, Some(0))?, change);
            // Use a nonzero offset to exercise endpoint rather than length.
            let offset = value / 2;
            assert_eq!(
                buffers.update(
                    stream,
                    StreamAccess {
                        offset,
                        length: value - offset,
                    },
                    time
                )?,
                change
            );
            assert_eq!(maxima.current_sum(), total);
            assert_eq!(buffers.current_sum(), total);
            let maxima_positions = maxima
                .streams()
                .iter()
                .map(|(id, history)| (id, history.maximum()))
                .collect::<Vec<_>>();
            let buffer_positions = buffers
                .streams()
                .iter()
                .map(|(id, history)| (id, history.maximum()))
                .collect::<Vec<_>>();
            assert_eq!(maxima_positions, buffer_positions);
            assert_eq!(
                maxima_positions
                    .iter()
                    .map(|(_, value)| *value)
                    .sum::<u64>(),
                total
            );
            expected_history.push((time, total));
            assert_eq!(maxima.sum_series(), expected_history);
            assert_eq!(buffers.sum_series(), expected_history);
        }
        assert_eq!(maxima.get_stream_max(999), None);
        assert_eq!(buffers.get_stream_max(999), None);
        Ok(())
    }

    #[test]
    fn quic_credit_counts_offsets_resets_and_not_retransmissions(
    ) -> Result<(), TrackerError> {
        use super::QuicStreamObservation;
        use super::QuicStreamTracker;
        let mut tracker = QuicStreamTracker::default();
        let frame = |offset, length| QuicStreamObservation::Frame {
            offset,
            length,
            fin: None,
        };
        for (id, time, observation, total) in [
            (0, 5.0, frame(Some(100), Some(50)), 150),
            (4, 2.0, frame(Some(0), Some(20)), 170),
            (0, 6.0, frame(Some(90), Some(30)), 170),
            (0, 7.0, frame(Some(140), Some(20)), 180),
            (
                4,
                8.0,
                QuicStreamObservation::Reset { final_size: 100 },
                260,
            ),
            (
                4,
                9.0,
                QuicStreamObservation::Reset { final_size: 100 },
                260,
            ),
            (8, 10.0, frame(Some(30), None), 290),
            (12, 11.0, frame(None, Some(5)), 295),
            (12, 12.0, frame(None, None), 295),
        ] {
            tracker.observe(id, observation, time)?;
            assert_eq!(tracker.current_sum(), total);
        }
        assert_eq!(tracker.chronological_sum_series()?.as_ref(), [
            (2.0, 20),
            (5.0, 170),
            (6.0, 170),
            (7.0, 180),
            (8.0, 260),
            (9.0, 260),
            (10.0, 290),
            (11.0, 295),
            (12.0, 295),
        ]);
        assert_eq!(frame(Some(0), Some(0)).frame_end(), Some(0));
        assert_eq!(frame(Some(0), None).frame_end(), None);
        assert_eq!(frame(None, Some(0)).frame_end(), None);
        Ok(())
    }

    #[test]
    fn quic_observation_overflow_preserves_history() -> Result<(), TrackerError> {
        use super::QuicStreamObservation;
        use super::QuicStreamTracker;
        let mut tracker = QuicStreamTracker::default();
        let frame = |offset, length| QuicStreamObservation::Frame {
            offset: Some(offset),
            length: Some(length),
            fin: None,
        };
        assert_eq!(
            tracker.observe(1, frame(u64::MAX, 1), 1.0),
            Err(TrackerError::StreamEndOverflow {
                stream_id: 1,
                offset: u64::MAX,
                length: 1
            })
        );
        assert!(tracker.streams().is_empty());
        tracker.observe(1, frame(u64::MAX - 2, 2), 2.0)?;
        assert_eq!(
            tracker.observe(2, frame(0, 1), 3.0),
            Err(TrackerError::RunningSumOverflow {
                stream_id: 2,
                total: u64::MAX,
                increment: 1
            })
        );
        assert_eq!(tracker.streams().len(), 1);
        assert_eq!(tracker.sum_series(), [(2.0, u64::MAX)]);
        Ok(())
    }

    #[test]
    fn ordered_and_duplicate_observations() -> Result<(), TrackerError> {
        check_updates(&[
            (0, 1000, 10.0, Some((0, 1000)), 1000),
            (0, 1000, 12.0, None, 1000),
            (0, 2000, 20.0, Some((1000, 2000)), 2000),
            (0, 3000, 30.0, Some((2000, 3000)), 3000),
        ])
    }

    #[test]
    fn interleaved_and_out_of_order_observations() -> Result<(), TrackerError> {
        check_updates(&[
            (0, 1000, 10.0, Some((0, 1000)), 1000),
            (1, 500, 12.0, Some((0, 500)), 1500),
            (0, 800, 8.0, None, 1500),
            (2, 2000, 15.0, Some((0, 2000)), 3500),
            (1, 1000, 18.0, Some((500, 1000)), 4000),
            (0, 1500, 20.0, Some((1000, 1500)), 4500),
        ])
    }

    #[test]
    fn chronological_totals_apply_initial_credit_only_to_observed_streams(
    ) -> Result<(), TrackerError> {
        let mut maxima = StreamMaxTracker::default();
        let mut buffers = StreamBufferTracker::default();
        for (id, time, extent, initial) in [
            (4, 10.0, 150, Some(100)),
            (8, 5.0, 20, Some(50)),
            (4, 2.0, 10, Some(100)),
            (8, 15.0, 80, Some(50)),
            (12, -2.0, 3, None),
        ] {
            maxima.update(id, extent, time, initial)?;
            let value = extent.max(initial.unwrap_or_default());
            buffers.update(
                id,
                StreamAccess {
                    offset: value / 2,
                    length: value - value / 2,
                },
                time,
            )?;
        }
        let expected =
            [(-2.0, 3), (2.0, 103), (5.0, 153), (10.0, 203), (15.0, 233)];
        assert_eq!(maxima.chronological_sum_series()?.as_ref(), expected);
        assert_eq!(buffers.chronological_sum_series()?.as_ref(), expected);
        assert_eq!(maxima.current_sum(), 233);
        assert_eq!(maxima.streams()[&4].points(), [(10.0, 150), (2.0, 10)]);
        Ok(())
    }

    #[test]
    fn exact_aggregate_boundary() -> Result<(), TrackerError> {
        check_updates(&[
            (1, u64::MAX - 2, 1.0, Some((0, u64::MAX - 2)), u64::MAX - 2),
            (2, 2, 2.0, Some((0, 2)), u64::MAX),
            (1, u64::MAX - 2, 3.0, None, u64::MAX),
        ])
    }

    #[test]
    fn zero_observations_are_distinct_from_unknown_streams(
    ) -> Result<(), TrackerError> {
        let mut maxima = StreamMaxTracker::default();
        let mut buffers = StreamBufferTracker::default();
        assert_eq!(maxima.update(7, 0, 1.0, Some(0))?, None);
        assert_eq!(
            buffers.update(
                7,
                StreamAccess {
                    offset: 0,
                    length: 0
                },
                1.0
            )?,
            None
        );
        assert_eq!(maxima.get_stream_max(7), Some(0));
        assert_eq!(buffers.get_stream_max(7), Some(0));
        assert_eq!(maxima.get_stream_max(8), None);
        assert_eq!(buffers.get_stream_max(8), None);
        assert_eq!(maxima.sum_series(), [(1.0, 0)]);
        assert_eq!(buffers.sum_series(), [(1.0, 0)]);
        Ok(())
    }

    #[test]
    fn initial_limit_is_metadata_not_a_frame() -> Result<(), TrackerError> {
        let mut tracker = StreamMaxTracker::default();
        tracker.update(0, 1000, 10.0, Some(500))?;
        tracker.update(0, 1500, 20.0, Some(700))?;
        assert_eq!(
            tracker.streams().get(&0).map(super::StreamHistory::points),
            Some([(10.0, 1000), (20.0, 1500)].as_slice())
        );
        assert_eq!(tracker.streams()[&0].initial(), Some(500));
        assert_eq!(tracker.current_sum(), 1500);
        Ok(())
    }

    #[test]
    fn initial_stream_credit_is_known_or_absent_and_never_regresses(
    ) -> Result<(), TrackerError> {
        let mut tracker = StreamMaxTracker::default();
        tracker.update(0, 20, 10.0, Some(100))?;
        tracker.update(0, 30, 12.0, Some(200))?;
        tracker.update(4, 40, 13.0, None)?;
        assert_eq!(tracker.get_stream_max(0), Some(100));
        assert_eq!(tracker.get_stream_max(4), Some(40));
        assert_eq!(tracker.current_sum(), 140);
        assert_eq!(tracker.streams()[&0].initial(), Some(100));
        assert_eq!(tracker.streams()[&0].points(), [(10.0, 20), (12.0, 30)]);
        assert_eq!(tracker.streams()[&4].points(), [(13.0, 40)]);
        Ok(())
    }

    #[test]
    fn late_initial_limits_replay_earlier_observations_and_preserve_raw_frames(
    ) -> Result<(), TrackerError> {
        let mut tracker = StreamMaxTracker::default();
        tracker.update(0, 200, 10.0, None)?;
        tracker.update(4, 20, 5.0, None)?;
        tracker.update(0, 10, 2.0, None)?;
        tracker.update(8, 10, 7.0, Some(15))?;
        tracker.hydrate_initial_limits(|id| match id {
            0 => Some(100),
            4 => Some(50),
            _ => Some(999),
        })?;
        assert_eq!(tracker.chronological_sum_series()?.as_ref(), [
            (2.0, 100),
            (5.0, 150),
            (7.0, 165),
            (10.0, 265),
        ]);
        assert_eq!(tracker.current_sum(), 265);
        assert_eq!(tracker.streams()[&0].points(), [(10.0, 200), (2.0, 10)]);
        assert_eq!(tracker.streams()[&4].initial(), Some(50));
        assert_eq!(tracker.streams()[&8].initial(), Some(15));
        tracker.update(4, 60, 3.0, Some(50))?;
        assert_eq!(tracker.chronological_sum_series()?.as_ref(), [
            (2.0, 100),
            (3.0, 160),
            (5.0, 160),
            (7.0, 175),
            (10.0, 275),
        ]);
        Ok(())
    }

    #[test]
    fn initial_limit_hydration_overflow_is_transactional(
    ) -> Result<(), TrackerError> {
        let mut tracker = StreamMaxTracker::default();
        tracker.update(0, 0, 1.0, None)?;
        tracker.update(4, 1, 2.0, None)?;
        assert!(matches!(
            tracker.hydrate_initial_limits(|_| Some(u64::MAX)),
            Err(TrackerError::RunningSumOverflow { .. })
        ));
        assert_eq!(tracker.current_sum(), 1);
        assert_eq!(tracker.streams()[&0].initial(), None);
        assert_eq!(tracker.streams()[&4].initial(), None);
        assert_eq!(tracker.chronological_sum_series()?.as_ref(), [
            (1.0, 0),
            (2.0, 1)
        ]);
        Ok(())
    }

    #[test]
    fn buffer_history_preserves_access_offsets_and_lengths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut tracker = StreamBufferTracker::default();
        tracker.update(
            0,
            StreamAccess {
                offset: 100,
                length: 500,
            },
            10.0,
        )?;
        tracker.update(
            0,
            StreamAccess {
                offset: 600,
                length: 300,
            },
            20.0,
        )?;
        let accesses = tracker
            .streams()
            .get(&0)
            .ok_or("missing access history")?
            .points();
        assert_eq!(
            accesses
                .iter()
                .map(|(time, access)| (*time, access.offset, access.length))
                .collect::<Vec<_>>(),
            [(10.0, 100, 500), (20.0, 600, 300)]
        );
        assert_eq!(tracker.get_stream_max(0), Some(900));
        Ok(())
    }

    #[test]
    fn rejects_aggregate_overflow_without_partial_state_changes(
    ) -> Result<(), TrackerError> {
        let mut maxima = StreamMaxTracker::default();
        let mut buffers = StreamBufferTracker::default();
        assert_eq!(
            maxima.update(5, u64::MAX, 1.0, Some(12))?,
            Some((0, u64::MAX))
        );
        assert_eq!(
            buffers.update(
                5,
                StreamAccess {
                    offset: u64::MAX,
                    length: 0
                },
                1.0
            )?,
            Some((0, u64::MAX))
        );
        let error = Err(TrackerError::RunningSumOverflow {
            stream_id: 6,
            total: u64::MAX,
            increment: 1,
        });
        assert_eq!(maxima.update(6, 1, 2.0, Some(0)), error);
        assert_eq!(
            buffers.update(
                6,
                StreamAccess {
                    offset: 0,
                    length: 1
                },
                2.0
            ),
            error
        );
        assert_eq!(maxima.get_stream_max(6), None);
        assert_eq!(buffers.get_stream_max(6), None);
        assert!(!maxima.streams().contains_key(&6));
        assert!(!buffers.streams().contains_key(&6));
        assert_eq!(maxima.sum_series(), [(1.0, u64::MAX)]);
        assert_eq!(buffers.sum_series(), [(1.0, u64::MAX)]);
        assert_eq!(maxima.update(5, 3, 3.0, Some(0))?, None);
        assert_eq!(
            buffers.update(
                5,
                StreamAccess {
                    offset: 0,
                    length: 10
                },
                3.0
            )?,
            None
        );
        assert_eq!(maxima.sum_series(), [(1.0, u64::MAX), (3.0, u64::MAX)]);
        assert_eq!(buffers.sum_series(), maxima.sum_series());
        assert_eq!(maxima.current_sum(), u64::MAX);
        assert_eq!(buffers.current_sum(), u64::MAX);
        Ok(())
    }

    #[test]
    fn rejects_overflowed_offsets_before_recording_history(
    ) -> Result<(), TrackerError> {
        let mut tracker = StreamBufferTracker::default();
        assert_eq!(
            tracker.update(
                7,
                StreamAccess {
                    offset: u64::MAX,
                    length: 1
                },
                10.0
            ),
            Err(TrackerError::StreamEndOverflow {
                stream_id: 7,
                offset: u64::MAX,
                length: 1
            })
        );
        assert_eq!(tracker.get_stream_max(7), None);
        assert_eq!(tracker.current_sum(), 0);
        assert!(tracker.streams().is_empty());
        assert_eq!(tracker.sum_series(), []);
        assert_eq!(
            tracker.update(
                7,
                StreamAccess {
                    offset: 2,
                    length: 3
                },
                11.0
            )?,
            Some((0, 5))
        );
        assert_eq!(tracker.current_sum(), 5);
        Ok(())
    }
}
