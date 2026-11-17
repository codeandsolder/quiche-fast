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

use std::collections::BTreeMap;

use super::checked_max_advance;
use super::TrackerError;
use crate::datastore::StreamAccess;

/// Tracks monotonically increasing stream buffer positions with efficient sum
/// calculation. Handles out-of-order events by taking max end position (offset
/// + length) seen per stream.
#[derive(Debug, Default)]
pub struct StreamBufferTracker {
    /// Full time series per stream with StreamAccess details.
    pub per_stream: BTreeMap<u64, Vec<(f64, StreamAccess)>>,

    /// Current maximum end position (offset + length) per stream.
    pub flat: BTreeMap<u64, u64>,

    /// Cumulative sum time series.
    pub sum_series: Vec<(f64, u64)>,

    /// Running sum for O(1) updates.
    running_sum: u64,
}

impl StreamBufferTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates stream buffer position, returning the change in maximum if any.
    /// Validation is atomic: invalid offsets or cumulative totals leave every
    /// tracker field unchanged.
    ///
    /// # Errors
    /// Returns `TrackerError` if the access endpoint or cumulative sum
    /// overflows.
    pub fn update(
        &mut self, stream_id: u64, access: StreamAccess, ev_time: f64,
    ) -> Result<Option<(u64, u64)>, TrackerError> {
        let new_end = access.offset.checked_add(access.length).ok_or(
            TrackerError::StreamEndOverflow {
                stream_id,
                offset: access.offset,
                length: access.length,
            },
        )?;
        let old_max = self.flat.get(&stream_id).copied().unwrap_or(0);
        let (new_max, new_sum) =
            checked_max_advance(stream_id, old_max, new_end, self.running_sum)?;

        self.per_stream
            .entry(stream_id)
            .or_default()
            .push((ev_time, access));
        let result = if new_max > old_max {
            self.flat.insert(stream_id, new_max);
            Some((old_max, new_max))
        } else {
            None
        };
        self.running_sum = new_sum;
        self.sum_series.push((ev_time, self.running_sum));
        Ok(result)
    }

    pub fn get_stream_max(&self, stream_id: u64) -> Option<u64> {
        self.flat.get(&stream_id).copied()
    }

    pub fn current_sum(&self) -> u64 {
        self.running_sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_empty() {
        let tracker = StreamBufferTracker::new();
        assert_eq!(tracker.current_sum(), 0);
        assert_eq!(tracker.get_stream_max(0), None);
        assert!(tracker.sum_series.is_empty());
        assert!(tracker.flat.is_empty());
    }

    #[test]
    fn test_tracker_single_stream_in_order() {
        let mut tracker = StreamBufferTracker::new();

        let result = tracker.update(
            0,
            StreamAccess {
                offset: 0,
                length: 1000,
            },
            10.0,
        );
        assert_eq!(result, Ok(Some((0, 1000))));
        assert_eq!(tracker.get_stream_max(0), Some(1000));
        assert_eq!(tracker.current_sum(), 1000);
        assert_eq!(tracker.sum_series, vec![(10.0, 1000)]);

        let result = tracker.update(
            0,
            StreamAccess {
                offset: 1000,
                length: 1000,
            },
            20.0,
        );
        assert_eq!(result, Ok(Some((1000, 2000))));
        assert_eq!(tracker.get_stream_max(0), Some(2000));
        assert_eq!(tracker.current_sum(), 2000);
        assert_eq!(tracker.sum_series, vec![(10.0, 1000), (20.0, 2000)]);
    }

    #[test]
    fn test_tracker_out_of_order_events() {
        let mut tracker = StreamBufferTracker::new();

        // Larger end position arrives first at t=20.
        let result = tracker.update(
            0,
            StreamAccess {
                offset: 1000,
                length: 1000,
            },
            20.0,
        );
        assert_eq!(result, Ok(Some((0, 2000))));
        assert_eq!(tracker.get_stream_max(0), Some(2000));
        assert_eq!(tracker.current_sum(), 2000);

        // Smaller end position arrives later at t=10 - should NOT update.
        let result = tracker.update(
            0,
            StreamAccess {
                offset: 0,
                length: 1000,
            },
            10.0,
        );
        assert_eq!(result, Ok(None));
        assert_eq!(tracker.get_stream_max(0), Some(2000));
        assert_eq!(tracker.current_sum(), 2000);

        assert_eq!(tracker.sum_series, vec![(20.0, 2000), (10.0, 2000)]);

        // Later, larger position arrives.
        let result = tracker.update(
            0,
            StreamAccess {
                offset: 2000,
                length: 1000,
            },
            30.0,
        );
        assert_eq!(result, Ok(Some((2000, 3000))));
        assert_eq!(tracker.get_stream_max(0), Some(3000));
        assert_eq!(tracker.current_sum(), 3000);
    }

    #[test]
    fn test_tracker_multiple_streams() {
        let mut tracker = StreamBufferTracker::new();

        assert!(tracker
            .update(
                0,
                StreamAccess {
                    offset: 0,
                    length: 1000,
                },
                10.0,
            )
            .is_ok());
        assert_eq!(tracker.current_sum(), 1000);

        assert!(tracker
            .update(
                1,
                StreamAccess {
                    offset: 0,
                    length: 500,
                },
                15.0,
            )
            .is_ok());
        assert_eq!(tracker.current_sum(), 1500);

        assert!(tracker
            .update(
                0,
                StreamAccess {
                    offset: 1000,
                    length: 500,
                },
                20.0,
            )
            .is_ok());
        assert_eq!(tracker.current_sum(), 2000);

        assert!(tracker
            .update(
                2,
                StreamAccess {
                    offset: 0,
                    length: 300,
                },
                25.0,
            )
            .is_ok());
        assert_eq!(tracker.current_sum(), 2300);

        assert_eq!(tracker.get_stream_max(0), Some(1500));
        assert_eq!(tracker.get_stream_max(1), Some(500));
        assert_eq!(tracker.get_stream_max(2), Some(300));
        assert_eq!(tracker.get_stream_max(999), None);
    }

    #[test]
    fn test_tracker_duplicate_values() {
        let mut tracker = StreamBufferTracker::new();

        let result = tracker.update(
            0,
            StreamAccess {
                offset: 0,
                length: 1000,
            },
            10.0,
        );
        assert_eq!(result, Ok(Some((0, 1000))));

        let result = tracker.update(
            0,
            StreamAccess {
                offset: 0,
                length: 1000,
            },
            20.0,
        );
        assert_eq!(result, Ok(None));

        assert_eq!(tracker.get_stream_max(0), Some(1000));
        assert_eq!(tracker.current_sum(), 1000);

        assert_eq!(tracker.sum_series.len(), 2);
        assert_eq!(tracker.sum_series, vec![(10.0, 1000), (20.0, 1000)]);
    }

    #[test]
    fn test_tracker_running_sum_correctness() {
        let mut tracker = StreamBufferTracker::new();

        assert!(tracker
            .update(
                0,
                StreamAccess {
                    offset: 0,
                    length: 1000,
                },
                1.0,
            )
            .is_ok());
        assert!(tracker
            .update(
                1,
                StreamAccess {
                    offset: 0,
                    length: 2000,
                },
                2.0,
            )
            .is_ok());
        assert!(tracker
            .update(
                2,
                StreamAccess {
                    offset: 0,
                    length: 1500,
                },
                3.0,
            )
            .is_ok());
        assert!(tracker
            .update(
                0,
                StreamAccess {
                    offset: 1000,
                    length: 200,
                },
                4.0,
            )
            .is_ok());

        let manual_sum: u64 = tracker.flat.values().sum();

        assert_eq!(tracker.current_sum(), manual_sum);
        assert_eq!(tracker.current_sum(), 4700);
    }

    #[test]
    fn test_tracker_preserves_stream_access() {
        let mut tracker = StreamBufferTracker::new();

        assert!(tracker
            .update(
                0,
                StreamAccess {
                    offset: 100,
                    length: 500,
                },
                10.0,
            )
            .is_ok());
        assert!(tracker
            .update(
                0,
                StreamAccess {
                    offset: 600,
                    length: 300,
                },
                20.0,
            )
            .is_ok());

        let stream_data = tracker.per_stream.get(&0).unwrap();
        assert_eq!(stream_data.len(), 2);
        assert_eq!(stream_data[0].1.offset, 100);
        assert_eq!(stream_data[0].1.length, 500);
        assert_eq!(stream_data[1].1.offset, 600);
        assert_eq!(stream_data[1].1.length, 300);

        assert_eq!(tracker.get_stream_max(0), Some(900));
    }

    #[test]
    fn rejects_overflowed_offsets_before_recording_any_history() {
        let mut tracker = StreamBufferTracker::new();
        let err = tracker.update(
            7,
            StreamAccess {
                offset: u64::MAX,
                length: 1,
            },
            10.0,
        );
        assert_eq!(
            err,
            Err(super::TrackerError::StreamEndOverflow {
                stream_id: 7,
                offset: u64::MAX,
                length: 1,
            })
        );
        assert_eq!(tracker.get_stream_max(7), None);
        assert_eq!(tracker.current_sum(), 0);
        assert!(tracker.per_stream.is_empty());
        assert!(tracker.flat.is_empty());
        assert!(tracker.sum_series.is_empty());

        // An invalid update cannot poison the next valid update.
        assert_eq!(
            tracker.update(
                7,
                StreamAccess {
                    offset: 2,
                    length: 3
                },
                11.0
            ),
            Ok(Some((0, 5)))
        );
        assert_eq!(tracker.current_sum(), 5);
    }

    #[test]
    fn rejects_cumulative_sum_overflow_without_partial_state_changes() {
        let mut tracker = StreamBufferTracker::new();
        assert_eq!(
            tracker.update(
                2,
                StreamAccess {
                    offset: u64::MAX,
                    length: 0,
                },
                1.0
            ),
            Ok(Some((0, u64::MAX)))
        );

        let err = tracker.update(
            3,
            StreamAccess {
                offset: 0,
                length: 1,
            },
            2.0,
        );
        assert_eq!(
            err,
            Err(super::TrackerError::RunningSumOverflow {
                stream_id: 3,
                total: u64::MAX,
                increment: 1,
            })
        );
        assert_eq!(tracker.current_sum(), u64::MAX);
        assert!(!tracker.flat.contains_key(&3));
        assert!(!tracker.per_stream.contains_key(&3));
        assert_eq!(tracker.sum_series, vec![(1.0, u64::MAX)]);

        // Repeated or out-of-order readings of a maximum are still recorded.
        assert_eq!(
            tracker.update(
                2,
                StreamAccess {
                    offset: 0,
                    length: 10
                },
                3.0
            ),
            Ok(None)
        );
        assert_eq!(tracker.sum_series, vec![(1.0, u64::MAX), (3.0, u64::MAX)]);
        assert_eq!(tracker.current_sum(), u64::MAX);
    }
}
