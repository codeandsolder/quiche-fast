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

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use datagram_socket::StreamClosureKind;

/// Stream-level HTTP/3 audit statistics recorded by
/// [`H3Driver`](crate::http3::driver::H3Driver).
#[derive(Debug)]
pub struct H3AuditStats {
    /// The stream ID of this session.
    stream_id: u64,
    /// The number of bytes sent over the stream.
    downstream_bytes_sent: AtomicU64,
    /// The number of bytes received over the stream.
    downstream_bytes_recvd: AtomicU64,
    /// A `STOP_SENDING` error code received from the peer.
    ///
    /// `None` indicates that no such error code has been recorded.
    recvd_stop_sending_error_code: AtomicCell<Option<u64>>,
    /// A `RESET_STREAM` error code received from the peer.
    ///
    /// `None` indicates that no such error code has been recorded.
    recvd_reset_stream_error_code: AtomicCell<Option<u64>>,
    /// A `STOP_SENDING` error code sent to the peer.
    ///
    /// `None` indicates that no such error code has been recorded.
    sent_stop_sending_error_code: AtomicCell<Option<u64>>,
    /// A `RESET_STREAM` error code sent to the peer.
    ///
    /// `None` indicates that no such error code has been recorded.
    sent_reset_stream_error_code: AtomicCell<Option<u64>>,
    /// Stream FIN received from the peer.
    recvd_stream_fin: AtomicCell<StreamClosureKind>,
    /// Stream FIN sent to the peer.
    sent_stream_fin: AtomicCell<StreamClosureKind>,
    /// Cumulative time between `HEADERS` failed flush and complete.
    ///
    /// Measured as the duration between the first moment a `HEADERS` frame was
    /// not flushed in full, and the moment that it was completely flushed.
    /// Measured across all `HEADERS` frames sent on the stream. A value of 0
    /// indicates there was no failed flushing.
    headers_flush_duration: AtomicCell<Duration>,
}

impl H3AuditStats {
    /// Creates an empty audit record for the stream.
    #[must_use = "the returned record tracks the stream statistics"]
    pub const fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            downstream_bytes_sent: AtomicU64::new(0),
            downstream_bytes_recvd: AtomicU64::new(0),
            recvd_stop_sending_error_code: AtomicCell::new(None),
            recvd_reset_stream_error_code: AtomicCell::new(None),
            sent_stop_sending_error_code: AtomicCell::new(None),
            sent_reset_stream_error_code: AtomicCell::new(None),
            recvd_stream_fin: AtomicCell::new(StreamClosureKind::None),
            sent_stream_fin: AtomicCell::new(StreamClosureKind::None),
            headers_flush_duration: AtomicCell::new(Duration::ZERO),
        }
    }

    /// The stream ID of this session.
    #[inline]
    #[must_use = "the ID identifies the audited stream"]
    pub const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// The number of bytes sent over the stream.
    #[inline]
    pub fn downstream_bytes_sent(&self) -> u64 {
        self.downstream_bytes_sent.load(Ordering::Relaxed)
    }

    /// The number of bytes received over the stream.
    #[inline]
    pub fn downstream_bytes_recvd(&self) -> u64 {
        self.downstream_bytes_recvd.load(Ordering::Relaxed)
    }

    /// A `STOP_SENDING` error code received from the peer.
    ///
    /// `None` indicates that no such error code has been recorded.
    #[inline]
    pub fn recvd_stop_sending_error_code(&self) -> Option<u64> {
        self.recvd_stop_sending_error_code.load()
    }

    /// A `RESET_STREAM` error code received from the peer.
    ///
    /// `None` indicates that no such error code has been recorded.
    #[inline]
    pub fn recvd_reset_stream_error_code(&self) -> Option<u64> {
        self.recvd_reset_stream_error_code.load()
    }

    /// A `STOP_SENDING` error code sent to the peer.
    ///
    /// `None` indicates that no such error code has been recorded.
    #[inline]
    pub fn sent_stop_sending_error_code(&self) -> Option<u64> {
        self.sent_stop_sending_error_code.load()
    }

    /// A `RESET_STREAM` error code sent to the peer.
    ///
    /// `None` indicates that no such error code has been recorded.
    #[inline]
    pub fn sent_reset_stream_error_code(&self) -> Option<u64> {
        self.sent_reset_stream_error_code.load()
    }

    /// Stream FIN received from the peer.
    #[inline]
    pub fn recvd_stream_fin(&self) -> StreamClosureKind {
        self.recvd_stream_fin.load()
    }

    /// Stream FIN sent to the peer.
    #[inline]
    pub fn sent_stream_fin(&self) -> StreamClosureKind {
        self.sent_stream_fin.load()
    }

    /// Cumulative time between `HEADERS` failed flush and complete.
    ///
    /// Measured as the duration between the first moment a `HEADERS` frame was
    /// not flushed in full, and the moment that it was completely flushed.
    /// Measured across all `HEADERS` frames sent on the stream. A value of 0
    /// indicates there was no failed flushing.
    #[inline]
    pub fn headers_flush_duration(&self) -> Duration {
        self.headers_flush_duration.load()
    }

    #[inline]
    pub fn add_downstream_bytes_sent(&self, bytes_sent: u64) {
        self.downstream_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_downstream_bytes_recvd(&self, bytes_recvd: u64) {
        self.downstream_bytes_recvd
            .fetch_add(bytes_recvd, Ordering::Relaxed);
    }

    #[inline]
    pub fn set_recvd_stop_sending_error_code(
        &self, recvd_stop_sending_error_code: u64,
    ) {
        self.recvd_stop_sending_error_code
            .store(Some(recvd_stop_sending_error_code));
    }

    #[inline]
    pub fn set_recvd_reset_stream_error_code(
        &self, recvd_reset_stream_error_code: u64,
    ) {
        self.recvd_reset_stream_error_code
            .store(Some(recvd_reset_stream_error_code));
    }

    #[inline]
    pub fn set_sent_stop_sending_error_code(
        &self, sent_stop_sending_error_code: u64,
    ) {
        self.sent_stop_sending_error_code
            .store(Some(sent_stop_sending_error_code));
    }

    #[inline]
    pub fn set_sent_reset_stream_error_code(
        &self, sent_reset_stream_error_code: u64,
    ) {
        self.sent_reset_stream_error_code
            .store(Some(sent_reset_stream_error_code));
    }

    #[inline]
    pub fn set_recvd_stream_fin(&self, recvd_stream_fin: StreamClosureKind) {
        self.recvd_stream_fin.store(recvd_stream_fin);
    }

    #[inline]
    pub fn set_sent_stream_fin(&self, sent_stream_fin: StreamClosureKind) {
        self.sent_stream_fin.store(sent_stream_fin);
    }

    #[inline]
    pub fn add_header_flush_duration(&self, duration: Duration) {
        let _ = self
            .headers_flush_duration
            .fetch_update(|current| Some(current.saturating_add(duration)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_wire_codes_are_distinct_from_missing() {
        let stats = H3AuditStats::new(4);
        assert_eq!(stats.recvd_stop_sending_error_code(), None);
        assert_eq!(stats.recvd_reset_stream_error_code(), None);
        assert_eq!(stats.sent_stop_sending_error_code(), None);
        assert_eq!(stats.sent_reset_stream_error_code(), None);
        stats.set_recvd_stop_sending_error_code(0);
        stats.set_recvd_reset_stream_error_code(octets::MAX_VAR_INT);
        stats.set_sent_stop_sending_error_code(42);
        stats.set_sent_reset_stream_error_code(1 << 32);
        assert_eq!(stats.recvd_stop_sending_error_code(), Some(0));
        assert_eq!(
            stats.recvd_reset_stream_error_code(),
            Some(octets::MAX_VAR_INT)
        );
        assert_eq!(stats.sent_stop_sending_error_code(), Some(42));
        assert_eq!(stats.sent_reset_stream_error_code(), Some(1 << 32));
    }

    #[test]
    fn flush_duration_accumulates_concurrent_updates_and_saturates() {
        let stats = H3AuditStats::new(0);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        stats.add_header_flush_duration(Duration::from_nanos(1));
                    }
                });
            }
        });
        assert_eq!(stats.headers_flush_duration(), Duration::from_nanos(4000));
        stats.add_header_flush_duration(Duration::MAX);
        assert_eq!(stats.headers_flush_duration(), Duration::MAX);
    }
}
