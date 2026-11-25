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

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::ready;
use std::task::Context;
use std::task::Poll;

use foundations::telemetry::log;
use futures::future::AbortHandle;
use futures::future::Abortable;
use futures_util::stream::FuturesUnordered;
use quiche::h3;
use tokio_stream::Stream;

use super::streams::StreamReady;
use super::streams::WaitForStream;
use super::streams::WaitKey;
use super::H3ConnectionError;
use super::H3ConnectionResult;

/// Tracks streams that are waiting on the application.
///
/// This tracks streams that are either waiting for upstream capacity (to write
/// more data to the app) or downstream data, i.e., data from the app to send
/// to the peer.
pub(super) struct WaitingStreams {
    /// Pending waits. A wait is aborted if the stream is cleaned up or reset
    /// by the peer.
    waits: FuturesUnordered<Abortable<WaitForStream>>,
    /// Abort handles keyed by the exact stream direction.
    handles: HashMap<WaitKey, AbortHandle>,
}

impl WaitingStreams {
    pub(super) fn new() -> Self {
        Self {
            waits: FuturesUnordered::new(),
            handles: HashMap::new(),
        }
    }

    /// Registers a pending stream and stores its abort handle by stream ID.
    pub(super) fn push(&mut self, wait: WaitForStream) -> H3ConnectionResult<()> {
        let key = wait.key();
        let Entry::Vacant(entry) = self.handles.entry(key) else {
            // Do not replace the live abort handle on a duplicate registration.
            log::error!(ratelimit=60/m; "duplicate stream wait"; "key" => ?key);
            return Err(H3ConnectionError::H3(h3::Error::Internal));
        };
        let (handle, registration) = AbortHandle::new_pair();
        entry.insert(handle);
        self.waits.push(Abortable::new(wait, registration));
        Ok(())
    }

    fn cancel(&mut self, key: WaitKey) {
        if let Some(handle) = self.handles.remove(&key) {
            handle.abort();
        }
    }

    /// Cancels the upstream-capacity wait for `stream_id`, if present.
    pub(super) fn cancel_upstream(&mut self, stream_id: u64) {
        self.cancel(WaitKey::Upstream(stream_id));
    }

    /// Cancels the downstream-data wait for `stream_id`, if present.
    pub(super) fn cancel_downstream(&mut self, stream_id: u64) {
        self.cancel(WaitKey::Downstream(stream_id));
    }

    /// Returns the number of live upstream-capacity waits.
    #[cfg(test)]
    pub fn upstream_len(&self) -> usize {
        self.handles
            .keys()
            .filter(|key| matches!(key, WaitKey::Upstream(_)))
            .count()
    }

    /// Returns the number of live downstream-data waits.
    #[cfg(test)]
    pub fn downstream_len(&self) -> usize {
        self.handles
            .keys()
            .filter(|key| matches!(key, WaitKey::Downstream(_)))
            .count()
    }
}

impl Stream for WaitingStreams {
    type Item = StreamReady;

    fn poll_next(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.waits).poll_next(cx)) {
                Some(Ok(ready)) => {
                    self.handles.remove(&ready.key());
                    return Poll::Ready(Some(ready));
                },
                Some(Err(_aborted)) => {
                    // Wait was cancelled. Ignore.
                },
                None => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt as _;
    use tokio::sync::mpsc;
    use tokio_stream::StreamExt as _;
    use tokio_util::sync::PollSender;

    use super::*;
    use crate::http3::driver::InboundFrame;
    use crate::http3::driver::OutboundFrame;

    fn downstream_wait(
        stream_id: u64,
    ) -> (mpsc::Sender<OutboundFrame>, WaitForStream) {
        let (tx, rx) = mpsc::channel(1);
        let wait = WaitForStream::downstream(stream_id, rx);

        (tx, wait)
    }

    fn upstream_wait(
        stream_id: u64,
    ) -> (mpsc::Receiver<InboundFrame>, WaitForStream) {
        let (tx, rx) = mpsc::channel(1);
        let wait = WaitForStream::upstream(stream_id, PollSender::new(tx));

        (rx, wait)
    }

    #[test]
    fn successful_readiness_removes_handle() -> crate::QuicResult<()> {
        let mut waiting = WaitingStreams::new();
        let (tx, wait) = downstream_wait(4);

        waiting.push(wait)?;
        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 1);

        tx.try_send(OutboundFrame::Body(Default::default(), false))
            .map_err(|_| "outbound frame queue rejected test frame")?;

        let ready = waiting.next().now_or_never();
        assert!(matches!(
            ready,
            Some(Some(StreamReady::Downstream(r))) if r.stream_id == 4
        ));
        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 0);
        Ok(())
    }

    #[test]
    fn canceled_wait_produces_no_readiness() -> crate::QuicResult<()> {
        let mut waiting = WaitingStreams::new();
        let (_tx, wait) = downstream_wait(4);

        waiting.push(wait)?;
        waiting.cancel_downstream(4);

        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 0);
        assert!(matches!(waiting.next().now_or_never(), Some(None)));
        Ok(())
    }

    #[test]
    fn upstream_cancel_preserves_downstream_wait() -> crate::QuicResult<()> {
        let mut waiting = WaitingStreams::new();
        let (_rx, upstream) = upstream_wait(4);
        let (tx, downstream) = downstream_wait(4);

        waiting.push(upstream)?;
        waiting.push(downstream)?;
        waiting.cancel_upstream(4);

        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 1);
        assert!(waiting.next().now_or_never().is_none());

        tx.try_send(OutboundFrame::Body(Default::default(), false))
            .map_err(|_| "outbound frame queue rejected test frame")?;

        let ready = waiting.next().now_or_never();
        assert!(matches!(
            ready,
            Some(Some(StreamReady::Downstream(r))) if r.stream_id == 4
        ));
        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 0);
        Ok(())
    }

    #[test]
    fn cancel_then_register_same_direction() -> crate::QuicResult<()> {
        let mut waiting = WaitingStreams::new();
        let (_tx, wait) = downstream_wait(4);

        waiting.push(wait)?;
        waiting.cancel_downstream(4);

        let (tx, wait) = downstream_wait(4);
        waiting.push(wait)?;

        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 1);
        assert!(waiting.next().now_or_never().is_none());

        tx.try_send(OutboundFrame::Body(Default::default(), false))
            .map_err(|_| "outbound frame queue rejected test frame")?;

        let ready = waiting.next().now_or_never();
        assert!(matches!(
            ready,
            Some(Some(StreamReady::Downstream(r))) if r.stream_id == 4
        ));
        assert_eq!(waiting.upstream_len(), 0);
        assert_eq!(waiting.downstream_len(), 0);
        Ok(())
    }

    #[test]
    fn duplicate_registration_preserves_original_cancellation_handle(
    ) -> crate::QuicResult<()> {
        let mut waiting = WaitingStreams::new();
        let (tx, wait) = downstream_wait(4);
        let (tx2, duplicate) = downstream_wait(4);
        waiting.push(wait)?;
        assert!(waiting.push(duplicate).is_err());
        assert!(tx2.is_closed());
        assert_eq!(waiting.downstream_len(), 1);
        waiting.cancel_downstream(4);
        assert!(matches!(waiting.next().now_or_never(), Some(None)));
        assert!(tx.is_closed());
        assert_eq!(waiting.downstream_len(), 0);
        Ok(())
    }

    #[test]
    fn completed_wait_is_safe_to_poll_again() -> crate::QuicResult<()> {
        use std::future::Future as _;
        let (tx, mut wait) = downstream_wait(4);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
        tx.try_send(OutboundFrame::Body(Default::default(), false))
            .map_err(|_| "outbound frame queue rejected test frame")?;
        assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
        assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
        Ok(())
    }
}
