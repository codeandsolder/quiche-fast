// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implements Kathleen Nichols' algorithm for tracking the minimum (or maximum)
// estimate of a stream of samples over some fixed time interval. (E.g.,
// the minimum RTT over the past five minutes.) The algorithm keeps track of
// the best, second best, and third best min (or max) estimates, maintaining an
// invariant that the measurement time of the n'th best >= n-1'th best.

// The algorithm works as follows. On a reset, all three estimates are set to
// the same sample. The second best estimate is then recorded in the second
// quarter of the window, and a third best estimate is recorded in the second
// half of the window, bounding the worst case error when the true min is
// monotonically increasing (or true max is monotonically decreasing) over the
// window.
//
// A new best sample replaces all three estimates, since the new best is lower
// (or higher) than everything else in the window and it is the most recent.
// The window thus effectively gets reset on every new min. The same property
// holds true for second best and third best estimates. Specifically, when a
// sample arrives that is better than the second best but not better than the
// best, it replaces the second and third best estimates but not the best
// estimate. Similarly, a sample that is better than the third best estimate
// but not the other estimates replaces only the third best estimate.
//
// Finally, when the best expires, it is replaced by the second best, which in
// turn is replaced by the third best. The newest sample replaces the third
// best.

use std::ops::Div;
use std::ops::Sub;

#[derive(Debug, Clone, Copy)]
struct Sample<T, I> {
    sample: T,
    time: I,
}

#[derive(Debug)]
pub struct WindowedFilter<T, I, D> {
    window_length: D,
    estimates: Option<[Sample<T, I>; 3]>,
}

impl<T, I, D> WindowedFilter<T, I, D>
where
    T: Ord + Copy,
    I: Sub<I, Output = D> + Copy,
    D: Ord + Div<usize, Output = D> + Copy,
{
    pub const fn new(window_length: D) -> Self {
        Self {
            window_length,
            estimates: None,
        }
    }

    pub fn get_best(&self) -> Option<T> {
        self.estimates.map(|[best, _, _]| best.sample)
    }

    /// Recompute stored values in measurement order, retaining their times.
    /// Returning None discards a sample.
    pub fn recompute(&mut self, mut update: impl FnMut(T) -> Option<T>) {
        if let Some(estimates) = self.estimates.take() {
            for estimate in estimates {
                if let Some(sample) = update(estimate.sample) {
                    self.update(sample, estimate.time);
                }
            }
        }
    }

    pub fn update(&mut self, new_sample: T, new_time: I) {
        let new = Sample {
            sample: new_sample,
            time: new_time,
        };

        let Some(estimates) = &mut self.estimates else {
            self.estimates = Some([new; 3]);
            return;
        };
        let [best, second, third] = estimates;

        // Reset for a new best or when even the newest estimate is too old.
        if new_sample > best.sample || new_time - third.time > self.window_length
        {
            *estimates = [new; 3];
            return;
        }

        if new_sample > second.sample {
            *second = new;
            *third = new;
        } else if new_sample > third.sample {
            *third = new;
        }

        if new_time - best.time > self.window_length {
            *best = *second;
            *second = *third;
            *third = new;
            if new_time - best.time > self.window_length {
                *best = *second;
                *second = *third;
            }
            return;
        }

        // Take a new second estimate in the second quarter of the window.
        if second.sample == best.sample &&
            new_time - second.time > self.window_length / 4
        {
            *second = new;
            *third = new;
            return;
        }

        // Take a new third estimate in the second half of the window.
        if third.sample == second.sample &&
            new_time - third.time > self.window_length / 2
        {
            *third = new;
        }
    }
}
