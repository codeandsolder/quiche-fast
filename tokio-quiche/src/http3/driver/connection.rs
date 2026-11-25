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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Poll;

use datagram_socket::AsSocketStats;
use datagram_socket::QuicAuditStats;
use datagram_socket::ShutdownConnection;
use datagram_socket::SocketStats;
use quiche::ConnectionId;

use super::client;
use super::server;
use super::DriverHooks;
use super::H3Controller;
use crate::quic::QuicConnectionStats;
use crate::QuicConnection;

pub type ClientH3Connection = H3Connection<client::ClientHooks>;
pub type ServerH3Connection = H3Connection<server::ServerHooks>;

/// A wrapper for an HTTP/3-driven [`QuicConnection`] together with the driver's
/// [`H3Controller`].
pub struct H3Connection<H: DriverHooks> {
    pub quic_connection: QuicConnection,
    pub h3_controller: H3Controller<H>,
}

impl<H: DriverHooks> H3Connection<H> {
    /// Bundles `quic_connection` and `h3_controller` into a new
    /// [`H3Connection`].
    #[must_use = "the returned value describes the HTTP/3 connection"]
    pub const fn new(
        quic_connection: QuicConnection, h3_controller: H3Controller<H>,
    ) -> Self {
        Self {
            quic_connection,
            h3_controller,
        }
    }

    /// The local address this connection listens on.
    #[must_use = "the returned value describes the HTTP/3 connection"]
    pub const fn local_addr(&self) -> SocketAddr {
        self.quic_connection.local_addr()
    }

    /// The remote address for this connection.
    #[must_use = "the returned value describes the HTTP/3 connection"]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.quic_connection.peer_addr()
    }

    /// The [`QuicConnection`]'s audit stats.
    #[must_use = "the returned value describes the HTTP/3 connection"]
    pub const fn audit_log_stats(&self) -> &Arc<QuicAuditStats> {
        self.quic_connection.audit_log_stats()
    }

    /// The [`QuicConnection`]'s [`quiche`] stats.
    #[must_use = "the returned value describes the HTTP/3 connection"]
    pub const fn stats(&self) -> &Arc<Mutex<QuicConnectionStats>> {
        self.quic_connection.stats()
    }

    /// The [`QuicConnection`]'s source connection ID.
    #[must_use = "the returned value describes the HTTP/3 connection"]
    pub const fn scid(&self) -> &ConnectionId<'static> {
        self.quic_connection.scid()
    }
}

impl<H: DriverHooks> ShutdownConnection for H3Connection<H> {
    #[inline]
    fn poll_shutdown(
        &mut self, cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.quic_connection.poll_shutdown(cx)
    }
}

impl<H: DriverHooks> AsSocketStats for H3Connection<H> {
    #[inline]
    fn as_socket_stats(&self) -> SocketStats {
        self.quic_connection.as_socket_stats()
    }

    #[inline]
    fn as_quic_stats(&self) -> Option<&Arc<QuicAuditStats>> {
        self.quic_connection.as_quic_stats()
    }
}
