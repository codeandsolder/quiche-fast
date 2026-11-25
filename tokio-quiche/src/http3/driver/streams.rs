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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

use datagram_socket::DgramBuffer;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use super::H3ConnectionError;
use super::H3ConnectionResult;
use super::InboundFrameSender;
use super::InboundFrameStream;
use super::OutboundFrame;
use super::OutboundFrameSender;
use super::OutboundFrameStream;
use crate::http3::H3AuditStats;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReadState {
    Open,
    FinPending,
    Closed,
}

pub(super) struct StreamCtx {
    /// Sends [`InboundFrame`]s to a local task, for example an `H3Body`.
    pub(super) send: Option<InboundFrameSender>,
    /// Receives [`OutboundFrame`]s from a local task.
    pub(super) recv: Option<OutboundFrameStream>,
    /// Stores the next [`OutboundFrame`] to write to the connection.
    /// This is used as temporary storage when waiting for `recv`.
    pub(super) queued_frame: Option<OutboundFrame>,
    pub(super) audit_stats: Arc<H3AuditStats>,
    /// Indicates the stream sent initial headers.
    pub(super) initial_headers_sent: bool,
    /// First time that a HEADERS frame was not fully flushed.
    pub(super) first_full_headers_flush_fail_time: Option<Instant>,
    /// Transport FIN can precede delivery of the final frame to the app.
    pub(super) read_state: ReadState,
    /// Indicates the stream sent fin or reset. No more data will be sent.
    pub(super) fin_or_reset_sent: bool,
}

impl StreamCtx {
    /// Creates a new [`StreamCtx`]. This method returns the [`StreamCtx`]
    /// itself as well as the sender/receiver that it communicates with.
    pub(super) fn new(
        stream_id: u64, capacity: usize,
    ) -> (Self, OutboundFrameSender, InboundFrameStream) {
        let (forward_sender, forward_receiver) = mpsc::channel(capacity);
        let (backward_sender, backward_receiver) = mpsc::channel(capacity);

        let ctx = Self {
            send: Some(PollSender::new(forward_sender)),
            recv: Some(backward_receiver),
            queued_frame: None,
            audit_stats: Arc::new(H3AuditStats::new(stream_id)),

            initial_headers_sent: false,
            first_full_headers_flush_fail_time: None,

            read_state: ReadState::Open,
            fin_or_reset_sent: false,
        };

        (ctx, PollSender::new(backward_sender), forward_receiver)
    }

    /// Moves the inbound sender to a wait for renewed application capacity.
    pub(super) fn wait_for_send(
        &mut self, stream_id: u64,
    ) -> H3ConnectionResult<WaitForStream> {
        let channel = self
            .send
            .take()
            .ok_or(H3ConnectionError::H3(quiche::h3::Error::Internal))?;
        Ok(WaitForStream::upstream(stream_id, channel))
    }

    /// Moves the outbound receiver to a wait for application data.
    pub(super) fn wait_for_recv(
        &mut self, stream_id: u64,
    ) -> H3ConnectionResult<WaitForStream> {
        let channel = self
            .recv
            .take()
            .ok_or(H3ConnectionError::H3(quiche::h3::Error::Internal))?;
        Ok(WaitForStream::downstream(stream_id, channel))
    }

    /// Handle the case when we received a `STOP_SENDING` frame. Note, that
    /// we'll only learn about a `STOP_SENDING` frame from the write path.
    /// Also note, that quiche will automatically send a `RESET_STREAM` frame
    /// in response when it receives a `STOP_SENDING` (as recommended by the
    /// RFC)
    pub(super) fn handle_recvd_stop_sending(&mut self, wire_err_code: u64) {
        // Update stats even if the stream is already closing.
        self.audit_stats
            .set_recvd_stop_sending_error_code(wire_err_code);

        if self.fin_or_reset_sent {
            // It is valid to receive STOP_SENDING after we already sent fin
            // (or a reset): the write side is already finished and there is
            // nothing left to do.
            return;
        }

        // We received a STOP_SENDING frame. This indicates that the
        // write direction has closed. We still need to continue
        // reading from the stream until we receive a RESET_FRAME or
        // `fin`.
        self.close_write();
    }

    pub(super) fn handle_recvd_reset(&mut self, wire_err_code: u64) {
        // We received a `RESET_STREAM` frame, which closes the read direction
        // but not the write direction. If the peer wants to shut down write,
        // it must also send STOP_SENDING
        self.audit_stats
            .set_recvd_reset_stream_error_code(wire_err_code);
        self.close_read();
    }

    pub(super) fn handle_sent_reset(&mut self, wire_err_code: u64) {
        self.audit_stats
            .set_sent_reset_stream_error_code(wire_err_code);
        self.close_write();
    }

    pub(super) fn handle_sent_stop_sending(&mut self, wire_err_code: u64) {
        self.audit_stats
            .set_sent_stop_sending_error_code(wire_err_code);
        // The peer must still send
        // FIN or `RESET_STREAM` with its final size, but `quiche` handles
        // that without an application read.
        self.close_read();
    }

    pub(super) const fn both_directions_done(&self) -> bool {
        matches!(self.read_state, ReadState::Closed) && self.fin_or_reset_sent
    }

    pub(super) fn close_read(&mut self) {
        self.read_state = ReadState::Closed;
        self.send = None;
    }

    pub(super) fn close_write(&mut self) {
        self.fin_or_reset_sent = true;
        self.recv = None;
        self.queued_frame = None;
    }
}

pub(super) struct FlowCtx {
    /// The receive side closes independently from the reliable stream body.
    send: Option<mpsc::Sender<DgramBuffer>>,
}

impl FlowCtx {
    /// Creates a request-bound datagram receiver.
    pub(super) fn new(capacity: usize) -> (Self, mpsc::Receiver<DgramBuffer>) {
        let (send, recv) = mpsc::channel(capacity);
        (Self { send: Some(send) }, recv)
    }

    /// Drops a datagram if the receiving task is closed or backpressured.
    pub(super) fn send_best_effort(&self, datagram: DgramBuffer) {
        if let Some(send) = &self.send {
            let _ = send.try_send(datagram);
        }
    }

    pub(super) fn close_read(&mut self) {
        self.send = None;
    }
}

/// One wait per stream and direction. Opposite directions are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum WaitKey {
    Upstream(u64),
    Downstream(u64),
}

pub(super) enum WaitForStream {
    Downstream {
        stream_id: u64,
        chan: Option<OutboundFrameStream>,
    },
    Upstream {
        stream_id: u64,
        chan: Option<InboundFrameSender>,
    },
}

impl WaitForStream {
    pub(super) const fn downstream(
        stream_id: u64, chan: OutboundFrameStream,
    ) -> Self {
        Self::Downstream {
            stream_id,
            chan: Some(chan),
        }
    }

    pub(super) const fn upstream(
        stream_id: u64, chan: InboundFrameSender,
    ) -> Self {
        Self::Upstream {
            stream_id,
            chan: Some(chan),
        }
    }

    pub(super) const fn key(&self) -> WaitKey {
        match self {
            Self::Downstream { stream_id, .. } => WaitKey::Downstream(*stream_id),
            Self::Upstream { stream_id, .. } => WaitKey::Upstream(*stream_id),
        }
    }
}

pub(super) enum StreamReady {
    Downstream(ReceivedDownstreamData),
    Upstream(HaveUpstreamCapacity),
}

impl StreamReady {
    pub(super) const fn key(&self) -> WaitKey {
        match self {
            Self::Downstream(ready) => WaitKey::Downstream(ready.stream_id),
            Self::Upstream(ready) => WaitKey::Upstream(ready.stream_id),
        }
    }
}

/// Keep ownership in the pending future until readiness, then hand it back
/// exactly once. Polling a completed wait is harmless.
fn poll_channel<C, T>(
    channel: &mut Option<C>, cx: &mut Context<'_>,
    poll: impl FnOnce(&mut C, &mut Context<'_>) -> Poll<T>,
) -> Poll<(C, T)> {
    let Some(mut chan) = channel.take() else {
        return Poll::Pending;
    };
    match poll(&mut chan, cx) {
        Poll::Ready(value) => Poll::Ready((chan, value)),
        Poll::Pending => {
            *channel = Some(chan);
            Poll::Pending
        },
    }
}

impl Future for WaitForStream {
    type Output = StreamReady;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Downstream { stream_id, chan } =>
                poll_channel(chan, cx, OutboundFrameStream::poll_recv).map(
                    |(chan, data)| {
                        StreamReady::Downstream(ReceivedDownstreamData {
                            stream_id: *stream_id,
                            chan,
                            data,
                        })
                    },
                ),
            Self::Upstream { stream_id, chan } =>
                poll_channel(chan, cx, InboundFrameSender::poll_reserve).map(
                    |(chan, _)| {
                        StreamReady::Upstream(HaveUpstreamCapacity {
                            stream_id: *stream_id,
                            chan,
                        })
                    },
                ),
        }
    }
}

pub(super) struct ReceivedDownstreamData {
    pub(super) stream_id: u64,
    pub(super) chan: OutboundFrameStream,
    pub(super) data: Option<OutboundFrame>,
}

pub(super) struct HaveUpstreamCapacity {
    pub(super) stream_id: u64,
    pub(super) chan: InboundFrameSender,
}
