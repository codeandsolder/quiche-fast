// Copyright (C) 2022, Cloudflare, Inc.
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
use std::collections::BTreeSet;

use super::SeriesBuildError;
use super::SeriesResult;
use crate::push_interp;
use crate::trackers::QuicStreamTracker;
use crate::trackers::StreamHistory;
use crate::trackers::StreamMaxTracker;
use crate::QlogPointu64;

/// Known initial limits and subsequent grants for transport directions with
/// actual STREAM, `RESET_STREAM` or `MAX_STREAM_DATA` evidence. These are
/// derived plot points, never invented raw `MAX_STREAM_DATA` frames.
#[derive(Default)]
pub(super) struct StreamCreditPlot {
    pub(super) streams: BTreeMap<u64, Vec<QlogPointu64>>,
    pub(super) total: Vec<QlogPointu64>,
}

fn credit_observations(
    grants: &[QlogPointu64], initial: Option<u64>,
    data_times: impl Iterator<Item = f64>,
) -> Vec<QlogPointu64> {
    let mut points = grants.to_vec();
    points.sort_by(|a, b| a.0.total_cmp(&b.0));
    let bounds = data_times.fold(None, |bounds: Option<(f64, f64)>, time| {
        Some(bounds.map_or((time, time), |(first, last)| {
            (first.min(time), last.max(time))
        }))
    });
    if let (Some((first, _)), Some(initial)) = (bounds, initial) {
        if points.first().is_none_or(|point| first < point.0) {
            points.insert(0, (first, initial));
        }
    }
    let mut maximum = initial.unwrap_or_default();
    for (_, limit) in &mut points {
        maximum = maximum.max(*limit);
        *limit = maximum;
    }
    if let (Some((_, end)), Some(&(last_time, last_limit))) =
        (bounds, points.last())
    {
        if end > last_time {
            points.push((end, last_limit));
        }
    }
    points
}

impl StreamCreditPlot {
    pub(super) fn build(
        grants: &StreamMaxTracker, data: &QuicStreamTracker,
        initial_for_stream: impl Fn(u64) -> Option<u64>,
    ) -> SeriesResult<Self> {
        let ids: BTreeSet<_> = grants
            .streams()
            .keys()
            .chain(data.streams().keys())
            .copied()
            .collect();
        let mut result = Self::default();
        let mut changes = Vec::new();
        for id in ids {
            let history = grants.streams().get(&id);
            let points = credit_observations(
                history.map_or(&[], StreamHistory::points),
                history
                    .and_then(StreamHistory::initial)
                    .or_else(|| initial_for_stream(id)),
                data.streams().get(&id).into_iter().flat_map(|history| {
                    history.points().iter().map(|point| point.0)
                }),
            );
            if points.is_empty() {
                continue;
            }
            let mut previous = 0;
            let series = result.streams.entry(id).or_default();
            for (time, value) in points {
                changes.push((time, id, value - previous));
                previous = value;
                push_interp(series, (time, value));
            }
        }
        changes.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut total = 0_u64;
        for (time, id, delta) in changes {
            total = total.checked_add(delta).ok_or(SeriesBuildError {
                stream_id: id,
                series: "observed_stream_credit",
            })?;
            push_interp(&mut result.total, (time, total));
        }
        Ok(result)
    }

    pub(super) fn update_bounds(
        &self, x_min: &mut f64, x_max: &mut f64, y_max: &mut u64,
    ) {
        if let (Some(first), Some(last)) = (self.total.first(), self.total.last())
        {
            *x_min = x_min.min(first.0);
            *x_max = x_max.max(last.0);
            *y_max = (*y_max).max(last.1);
        }
    }
}
