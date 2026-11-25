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

#[cfg(not(target_has_atomic = "64"))]
use portable_atomic::AtomicU64;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::SystemTime;

pub trait AsSocketStats {
    fn as_socket_stats(&self) -> SocketStats;

    fn as_quic_stats(&self) -> Option<&Arc<QuicAuditStats>> {
        None
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SocketStats {
    pub pmtu: u16,
    pub rtt_us: i64,
    pub min_rtt_us: i64,
    pub max_rtt_us: i64,
    pub rtt_var_us: i64,
    pub cwnd: u64,
    pub total_pto_count: u64,
    pub packets_sent: u64,
    pub packets_recvd: u64,
    pub packets_lost: u64,
    pub packets_lost_spurious: u64,
    pub packets_retrans: u64,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
    pub bytes_lost: u64,
    pub bytes_retrans: u64,
    pub bytes_unsent: u64,
    pub delivery_rate: u64,
    pub max_bandwidth: Option<u64>,
    pub startup_exit: Option<StartupExit>,
    pub bytes_in_flight_duration_us: u64,
}

/// Statistics from when a CCA first exited the startup phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupExit {
    pub cwnd: usize,
    pub bandwidth: Option<u64>,
    pub reason: StartupExitReason,
}

/// The reason a CCA exited the startup phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupExitReason {
    /// Exit slow start or BBR startup due to excessive loss
    Loss,

    /// Exit BBR startup due to bandwidth plateau.
    BandwidthPlateau,

    /// Exit BBR startup due to persistent queue.
    PersistentQueue,

    /// Exit `HyStart`++ conservative slow start after the max rounds allowed.
    ConservativeSlowStartRounds,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A connection-close code and its wire-level namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicCloseCode {
    Transport(u64),
    Application(u64),
}

impl QuicCloseCode {
    #[must_use = "the namespace is part of the close code"]
    pub const fn from_parts(is_app: bool, code: u64) -> Self {
        if is_app {
            Self::Application(code)
        } else {
            Self::Transport(code)
        }
    }
}

#[derive(Debug)]
pub struct QuicAuditStats {
    peer_close_code: OnceLock<QuicCloseCode>,
    local_close_code: OnceLock<QuicCloseCode>,
    transport_handshake_duration: OnceLock<Duration>,
    transport_handshake_start: OnceLock<SystemTime>,
    connection_close_reason: OnceLock<BoxError>,
    /// Max recorded bandwidth.
    max_bandwidth: AtomicU64,
    /// Loss at max recorded bandwidth.
    max_loss_pct: AtomicU8,
    /// The value of the first `SO_RECVMARK` control message received for the
    /// connection.
    ///
    /// Linux-only.
    #[cfg(target_os = "linux")]
    initial_so_mark: OnceLock<[u8; 4]>,
    /// The server's chosen QUIC connection ID.
    ///
    /// The QUIC connection ID is presently an array of 20 bytes (160 bits)
    pub quic_connection_id: Vec<u8>,
}

impl QuicAuditStats {
    #[inline]
    #[must_use = "the returned statistics object holds the per-connection counters"]
    pub fn new(quic_connection_id: Vec<u8>) -> Self {
        Self {
            peer_close_code: OnceLock::new(),
            local_close_code: OnceLock::new(),
            transport_handshake_duration: OnceLock::new(),
            transport_handshake_start: OnceLock::new(),
            connection_close_reason: OnceLock::new(),
            max_bandwidth: AtomicU64::new(0),
            max_loss_pct: AtomicU8::new(0),
            #[cfg(target_os = "linux")]
            initial_so_mark: OnceLock::new(),
            quic_connection_id,
        }
    }

    #[must_use = "the code identifies why the peer closed the connection"]
    pub fn peer_close_code(&self) -> Option<QuicCloseCode> {
        self.peer_close_code.get().copied()
    }

    #[must_use = "the code identifies why this endpoint closed the connection"]
    pub fn local_close_code(&self) -> Option<QuicCloseCode> {
        self.local_close_code.get().copied()
    }

    pub fn set_peer_close_code(&self, code: QuicCloseCode) {
        let _ = self.peer_close_code.set(code);
    }

    pub fn set_local_close_code(&self, code: QuicCloseCode) {
        let _ = self.local_close_code.set(code);
    }

    /// None until the transport handshake actually completes.
    #[must_use = "an incomplete handshake has no measured duration"]
    pub fn transport_handshake_duration(&self) -> Option<Duration> {
        self.transport_handshake_duration.get().copied()
    }

    pub fn set_transport_handshake_start(&self, start_time: SystemTime) {
        let _ = self.transport_handshake_start.set(start_time);
    }

    pub fn set_transport_handshake_duration(&self, duration: Duration) {
        let _ = self.transport_handshake_duration.set(duration);
    }

    #[must_use = "the timestamp anchors the handshake"]
    pub fn transport_handshake_start(&self) -> Option<SystemTime> {
        self.transport_handshake_start.get().copied()
    }

    #[must_use = "the first worker failure explains connection termination"]
    pub fn connection_close_reason(
        &self,
    ) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.connection_close_reason.get().map(Box::as_ref)
    }

    pub fn set_connection_close_reason(&self, error: BoxError) {
        let _ = self.connection_close_reason.set(error);
    }

    #[inline]
    pub fn set_max_bandwidth(&self, max_bandwidth: u64) {
        self.max_bandwidth.store(max_bandwidth, Ordering::Release);
    }

    #[inline]
    pub fn max_bandwidth(&self) -> u64 {
        self.max_bandwidth.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_max_loss_pct(&self, max_loss_pct: u8) {
        self.max_loss_pct.store(max_loss_pct, Ordering::Release);
    }

    #[inline]
    pub fn max_loss_pct(&self) -> u8 {
        self.max_loss_pct.load(Ordering::Acquire)
    }

    #[inline]
    #[cfg(target_os = "linux")]
    pub fn set_initial_so_mark_data(&self, value: Option<[u8; 4]>) {
        if let Some(inner) = value {
            let _ = self.initial_so_mark.set(inner);
        }
    }

    #[inline]
    #[cfg(target_os = "linux")]
    pub fn initial_so_mark_data(&self) -> Option<&[u8; 4]> {
        self.initial_so_mark.get()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StreamClosureKind {
    None,
    Implicit,
    Explicit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_handshake_publication_is_write_once() {
        let stats = Arc::new(QuicAuditStats::new(Vec::new()));
        assert_eq!(stats.transport_handshake_duration(), None);
        assert_eq!(stats.transport_handshake_start(), None);
        let start = SystemTime::now();
        stats.set_transport_handshake_start(start);
        let duration = Duration::MAX;
        std::thread::scope(|scope| {
            scope.spawn(|| stats.set_transport_handshake_duration(duration));
        });
        stats.set_transport_handshake_duration(Duration::ZERO);
        stats.set_transport_handshake_start(SystemTime::UNIX_EPOCH);
        assert_eq!(stats.transport_handshake_start(), Some(start));
        assert_eq!(stats.transport_handshake_duration(), Some(duration));
    }

    #[test]
    fn audit_close_publication_preserves_namespace_and_first_failure() {
        let stats = QuicAuditStats::new(Vec::new());
        assert_eq!(stats.peer_close_code(), None);
        assert_eq!(stats.local_close_code(), None);
        assert!(stats.connection_close_reason().is_none());
        stats.set_peer_close_code(QuicCloseCode::Transport(0));
        stats.set_local_close_code(QuicCloseCode::Application(u64::MAX));
        stats.set_local_close_code(QuicCloseCode::Transport(1));
        stats.set_connection_close_reason(Box::new(std::io::Error::other(
            "first",
        )));
        stats.set_connection_close_reason(Box::new(std::io::Error::other(
            "second",
        )));
        assert_eq!(stats.peer_close_code(), Some(QuicCloseCode::Transport(0)));
        assert_eq!(
            stats.local_close_code(),
            Some(QuicCloseCode::Application(u64::MAX))
        );
        assert_eq!(
            stats
                .connection_close_reason()
                .map(ToString::to_string)
                .as_deref(),
            Some("first")
        );
    }
}
