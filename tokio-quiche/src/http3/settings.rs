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
use tokio::time::Instant;

use crate::http3::driver::H3ConnectionError;
use crate::quic::QuicheConnection;
use foundations::telemetry::log;

/// Unified configuration parameters for
/// [`H3Driver`](crate::http3::driver::H3Driver)s.
#[derive(Default, Clone, Debug)]
#[non_exhaustive]
pub struct Http3Settings {
    /// Maximum number of requests a
    /// [`ServerH3Driver`](crate::http3::driver::ServerH3Driver) allows per
    /// connection.
    pub max_requests_per_connection: Option<u64>,
    /// Maximum size of a single `HEADERS` frame, in bytes.
    pub max_header_list_size: Option<u64>,
    /// Maximum value the QPACK encoder is permitted to set for the dynamic
    /// table capacity. See <https://www.rfc-editor.org/rfc/rfc9204.html#name-maximum-dynamic-table-capac>
    pub qpack_max_table_capacity: Option<u64>,
    /// Upper bound on the number of streams that can be blocked on the QPACK
    /// decoder. See <https://www.rfc-editor.org/rfc/rfc9204.html#name-blocked-streams>
    pub qpack_blocked_streams: Option<u64>,
    /// Timeout between starting the QUIC handshake and receiving the first
    /// request on a connection. Only applicable to
    /// [`ServerH3Driver`](crate::http3::driver::ServerH3Driver).
    pub post_accept_timeout: Option<Duration>,
    /// Set the `SETTINGS_ENABLE_CONNECT_PROTOCOL` HTTP/3 setting.
    /// See <https://www.rfc-editor.org/rfc/rfc9220#section-3-2>
    pub enable_extended_connect: bool,
    /// Maximum size, in bytes, of the buffer the driver uses to read HTTP/3
    /// body data out of quiche before forwarding it upstream.
    ///
    /// The buffer is sized dynamically to the amount of data currently
    /// readable on a stream (which is itself bounded by the QUIC flow-control
    /// window and the size of the buffered QUIC STREAM frames), but a single
    /// read will never allocate more than this cap. This bounds the memory a
    /// single (potentially adversarial) stream can force the driver to
    /// allocate.
    ///
    /// When unset or `Some(0)`, the driver defaults to 16 KiB.
    pub max_recv_body_buf_size: Option<usize>,
}

impl From<&Http3Settings> for quiche::h3::Config {
    fn from(value: &Http3Settings) -> Self {
        let mut config = Self::new();

        if let Some(v) = value.max_header_list_size {
            config.set_max_field_section_size(v);
        }

        if let Some(v) = value.qpack_max_table_capacity {
            config.set_qpack_max_table_capacity(v);
        }

        if let Some(v) = value.qpack_blocked_streams {
            config.set_qpack_blocked_streams(v);
        }

        if value.enable_extended_connect {
            config.enable_extended_connect(true);
        }

        config
    }
}

/// The server has exactly one connection-start deadline. Store its absolute
/// instant directly rather than maintaining an allocated delay queue and a
/// separate cancellation token.
pub(crate) struct Http3SettingsEnforcer {
    max_requests_per_connection: Option<u64>,
    post_accept_timeout: Option<Duration>,
    deadline: Option<Instant>,
}

impl From<&Http3Settings> for Http3SettingsEnforcer {
    fn from(value: &Http3Settings) -> Self {
        Self {
            max_requests_per_connection: value.max_requests_per_connection,
            post_accept_timeout: value.post_accept_timeout,
            deadline: None,
        }
    }
}

impl Http3SettingsEnforcer {
    /// Whether the request count reached the configured limit.
    pub const fn enforce_requests_limit(&self, request_count: u64) -> bool {
        match self.max_requests_per_connection {
            Some(limit) => request_count >= limit,
            None => false,
        }
    }

    /// Arm the deadline relative to the beginning of the QUIC handshake.
    pub fn arm_post_accept(
        &mut self, start: std::time::Instant,
    ) -> Result<(), H3ConnectionError> {
        self.deadline = match self.post_accept_timeout {
            Some(timeout) => Some(Instant::from_std(
                start
                    .checked_add(timeout)
                    .ok_or(H3ConnectionError::H3(quiche::h3::Error::Internal))?,
            )),
            None => None,
        };
        Ok(())
    }

    /// The first request satisfies the deadline; cancellation is idempotent.
    pub const fn cancel_post_accept(&mut self) {
        self.deadline = None;
    }

    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// A ready application or network event cannot mask an expired deadline.
    pub fn check_deadline(
        &mut self, qconn: &mut QuicheConnection,
    ) -> Result<(), H3ConnectionError> {
        if self
            .deadline
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            self.cancel_post_accept();
            log::debug!("connection timed out due to post-accept-timeout"; "scid" => ?qconn.source_id());
            // Preserve the timeout as the primary failure even if transport
            // closure was already underway.
            let _ =
                qconn.close(true, quiche::h3::WireErrorCode::NoError as u64, &[]);
            return Err(H3ConnectionError::PostAcceptTimeout);
        }
        Ok(())
    }

    /// Wait for the absolute deadline. Dropping the future on another event
    /// neither cancels nor extends it.
    pub async fn wait_for_timeout(
        &mut self, qconn: &mut QuicheConnection,
    ) -> Result<(), H3ConnectionError> {
        let Some(deadline) = self.deadline else {
            return std::future::pending().await;
        };
        tokio::time::sleep_until(deadline).await;
        self.check_deadline(qconn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_accept_deadline_includes_handshake_and_can_be_cancelled(
    ) -> crate::QuicResult<()> {
        let timeout = Duration::from_secs(5);
        let settings = Http3Settings {
            post_accept_timeout: Some(timeout),
            ..Http3Settings::default()
        };
        let mut enforcer = Http3SettingsEnforcer::from(&settings);
        let start = std::time::Instant::now() - Duration::from_secs(2);
        enforcer.arm_post_accept(start)?;
        assert_eq!(
            enforcer.deadline(),
            Some(Instant::from_std(start + timeout))
        );
        enforcer.cancel_post_accept();
        enforcer.cancel_post_accept();
        assert!(enforcer.deadline().is_none());
        Ok(())
    }

    #[test]
    fn impossible_deadline_is_reported_instead_of_panicking() {
        let settings = Http3Settings {
            post_accept_timeout: Some(Duration::MAX),
            ..Http3Settings::default()
        };
        let mut enforcer = Http3SettingsEnforcer::from(&settings);
        assert!(enforcer.arm_post_accept(std::time::Instant::now()).is_err());
        assert!(enforcer.deadline().is_none());
    }
}
