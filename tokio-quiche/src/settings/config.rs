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

use foundations::telemetry::log;
use std::borrow::Cow;
use std::fs::File;
use std::sync::Arc;
use std::time::Duration;

use qlog::writer::QlogCompression;

use crate::quic::ConnectionHook;
use crate::result::QuicResult;
use crate::settings::CertificateKind;
use crate::settings::ConnectionParams;
use crate::settings::TlsCertificatePaths;
use crate::socket::SocketCapabilities;
use crate::socket::SocketCapability;

/// Whether `--cfg capture_keylogs` was set at build time. We keep supporting
/// the `capture_keylogs` feature for backward compatibility.
const KEYLOGFILE_ENABLED: bool =
    cfg!(capture_keylogs) || cfg!(feature = "capture_keylogs");

/// Internal representation of the combined configuration for a QUIC connection.
pub struct Config {
    core: quiche::Config,
    pub disable_client_ip_validation: bool,
    pub qlog_dir: Option<String>,
    pub qlog_compression: QlogCompression,
    pub enable_expensive_packet_count_metrics: bool,
    pub keylog_file: Option<File>,
    pub listen_backlog: usize,
    pub handshake_timeout: Option<Duration>,
    pub pool_send_buffer: bool,
    socket_capabilities: SocketCapabilities,
    pub connection_hook: Option<Arc<dyn ConnectionHook + Send + Sync + 'static>>,
}

impl AsMut<quiche::Config> for Config {
    fn as_mut(&mut self) -> &mut quiche::Config {
        &mut self.core
    }
}

impl Config {
    pub(crate) fn new(
        params: &ConnectionParams, socket_capabilities: SocketCapabilities,
    ) -> QuicResult<Self> {
        let quic_settings = &params.settings;
        validate_runtime_settings(quic_settings)?;
        let keylog_path = quic_settings.keylog_file.as_ref().map_or_else(
            || std::env::var_os("SSLKEYLOGFILE").map(Cow::from),
            |path| Some(Cow::Borrowed(path.as_ref())),
        );
        let keylog_file = keylog_path.and_then(|path| if KEYLOGFILE_ENABLED {
                File::options().create(true).append(true).open(path)
                    .inspect_err(|e| {
                        log::warn!("failed to open SSLKEYLOGFILE"; "error" => e);
                    })
                    .ok()
            } else {
                log::warn!("SSLKEYLOGFILE is set, but `--cfg capture_keylogs` was not enabled. No keys will be logged.");
                None
            });

        // Preserve the typed capability set instead of duplicating individual
        // flags. The effective set also respects transport pacing policy.
        let socket_capabilities =
            if cfg!(feature = "gcongestion") && !quic_settings.enable_pacing {
                socket_capabilities.without(SocketCapability::TransmitTime)
            } else {
                socket_capabilities
            };

        Ok(Self {
            core: make_quiche_config(params, keylog_file.is_some())?,
            disable_client_ip_validation: quic_settings
                .disable_client_ip_validation,
            qlog_dir: quic_settings.qlog_dir.clone(),
            qlog_compression: quic_settings.qlog_compression,
            enable_expensive_packet_count_metrics: quic_settings
                .enable_expensive_packet_count_metrics,
            keylog_file,
            listen_backlog: quic_settings.listen_backlog,
            handshake_timeout: quic_settings.handshake_timeout,
            pool_send_buffer: quic_settings.pool_send_buffer,
            socket_capabilities,
            connection_hook: params.hooks.connection_hook.clone(),
        })
    }

    pub(crate) const fn socket_capabilities(&self) -> SocketCapabilities {
        self.socket_capabilities
    }
}

/// Validate values before constructing runtime queues or timers.
fn validate_runtime_settings(
    settings: &super::QuicSettings,
) -> std::io::Result<()> {
    use std::io::Error;
    use std::io::ErrorKind;
    if !(1..=tokio::sync::Semaphore::MAX_PERMITS)
        .contains(&settings.listen_backlog)
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "listen_backlog is outside the supported channel capacity",
        ));
    }
    if settings.handshake_timeout.is_some_and(|timeout| {
        std::time::Instant::now().checked_add(timeout).is_none()
    }) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "handshake_timeout exceeds the supported monotonic clock range",
        ));
    }
    Ok(())
}

fn make_quiche_config(
    params: &ConnectionParams, should_log_keys: bool,
) -> QuicResult<quiche::Config> {
    let ssl_ctx_builder = params
        .hooks
        .connection_hook
        .as_ref()
        .zip(params.tls_cert)
        .map(|(hook, tls)| hook.create_custom_ssl_context_builder(tls))
        .transpose()?
        .flatten();

    let mut config = if let Some(builder) = ssl_ctx_builder {
        quiche::Config::with_btls_ssl_ctx_builder(
            quiche::PROTOCOL_VERSION,
            builder,
        )?
    } else {
        quiche_config_with_tls(params.tls_cert)?
    };

    let quic_settings = &params.settings;

    let alpns: Vec<&[u8]> =
        quic_settings.alpn.iter().map(Vec::as_slice).collect();
    config.set_application_protos(&alpns)?;

    if let Some(timeout) = quic_settings.max_idle_timeout {
        let ms = timeout
            .as_millis()
            .try_into()
            .map_err(|_| "QuicSettings::max_idle_timeout exceeds u64")?;
        config.set_max_idle_timeout(ms);
    }

    config.enable_dgram(
        quic_settings.enable_dgram,
        quic_settings.dgram_recv_max_queue_len,
        quic_settings.dgram_send_max_queue_len,
    );

    config.set_max_recv_udp_payload_size(quic_settings.max_recv_udp_payload_size);
    config.set_max_send_udp_payload_size(quic_settings.max_send_udp_payload_size);
    config.set_initial_max_data(quic_settings.initial_max_data);
    config.set_initial_max_stream_data_bidi_local(
        quic_settings.initial_max_stream_data_bidi_local,
    );
    config.set_initial_max_stream_data_bidi_remote(
        quic_settings.initial_max_stream_data_bidi_remote,
    );
    config.set_initial_max_stream_data_uni(
        quic_settings.initial_max_stream_data_uni,
    );
    config.set_initial_max_streams_bidi(quic_settings.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(quic_settings.initial_max_streams_uni);
    config.set_disable_active_migration(quic_settings.disable_active_migration);
    config
        .set_active_connection_id_limit(quic_settings.active_connection_id_limit);
    config.set_cc_algorithm_name(quic_settings.cc_algorithm.as_str())?;
    config.set_initial_congestion_window_packets(
        quic_settings.initial_congestion_window_packets,
    );
    config.set_enable_relaxed_loss_threshold(
        quic_settings.enable_relaxed_loss_threshold,
    );
    config.discover_pmtu(quic_settings.discover_path_mtu);
    config.set_pmtud_max_probes(quic_settings.pmtud_max_probes);
    config.enable_hystart(quic_settings.enable_hystart);

    config.enable_pacing(quic_settings.enable_pacing);
    if let Some(max_pacing_rate) = quic_settings.max_pacing_rate {
        config.set_max_pacing_rate(max_pacing_rate);
    }

    if quic_settings.verify_peer {
        config.verify_peer(quic_settings.verify_peer);
    }

    config.set_max_connection_window(quic_settings.max_connection_window);
    config.set_max_stream_window(quic_settings.max_stream_window);
    config.set_enable_send_streams_blocked(
        quic_settings.enable_send_streams_blocked,
    );
    config.grease(quic_settings.grease);
    config.set_max_amplification_factor(quic_settings.max_amplification_factor);
    config.set_send_capacity_factor(quic_settings.send_capacity_factor);
    config.set_ack_delay_exponent(quic_settings.ack_delay_exponent);
    config.set_max_ack_delay(quic_settings.max_ack_delay);
    config.set_path_challenge_recv_max_queue_len(
        quic_settings.max_path_challenge_recv_queue_len,
    );
    config.set_stateless_reset_token(quic_settings.stateless_reset_token);
    config.set_disable_dcid_reuse(quic_settings.disable_dcid_reuse);

    if let Some(track_unknown_transport_params) =
        quic_settings.track_unknown_transport_parameters
    {
        config.enable_track_unknown_transport_parameters(
            track_unknown_transport_params,
        );
    }
    if params.settings.enable_early_data {
        config.enable_early_data();
    }

    if should_log_keys {
        config.log_keys();
    }

    Ok(config)
}

fn quiche_config_with_tls(
    tls_cert: Option<TlsCertificatePaths>,
) -> QuicResult<quiche::Config> {
    let Some(tls) = tls_cert else {
        return Ok(quiche::Config::new(quiche::PROTOCOL_VERSION)?);
    };

    match tls.kind {
        #[cfg(not(feature = "rpk"))]
        CertificateKind::RawPublicKey => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw public key certificates require the `rpk` feature",
        )
        .into()),
        #[cfg(feature = "rpk")]
        CertificateKind::RawPublicKey => {
            // Build an
            // `SslCredential` configured for raw public keys and add it
            // to a regular `SslContextBuilder` via `add_credential`.
            let raw_public_key = read_file(tls.cert)?;
            let raw_private_key = read_file(tls.private_key)?;
            let pkey = btls::pkey::PKey::private_key_from_pem(&raw_private_key)?;

            let mut credential_builder =
                btls::ssl::SslCredential::new_raw_public_key()?;
            credential_builder.set_spki_bytes(Some(&raw_public_key))?;
            credential_builder.set_private_key(&pkey)?;
            let credential = credential_builder.build();

            let mut ssl_ctx_builder =
                btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls())?;
            ssl_ctx_builder.add_credential(&credential)?;

            Ok(quiche::Config::with_btls_ssl_ctx_builder(
                quiche::PROTOCOL_VERSION,
                ssl_ctx_builder,
            )?)
        },
        CertificateKind::X509 => {
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
            config.load_cert_chain_from_pem_file(tls.cert)?;
            config.load_priv_key_from_pem_file(tls.private_key)?;
            Ok(config)
        },
    }
}

#[cfg(feature = "rpk")]
fn read_file(path: &str) -> QuicResult<Vec<u8>> {
    use anyhow::Context as _;
    std::fs::read(path)
        .with_context(|| format!("read {path}"))
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Hooks;
    use crate::settings::QuicSettings;

    #[test]
    fn invalid_runtime_limits_are_rejected_before_queue_creation() {
        for listen_backlog in [0, tokio::sync::Semaphore::MAX_PERMITS + 1] {
            let settings = QuicSettings {
                listen_backlog,
                ..QuicSettings::default()
            };
            assert!(validate_runtime_settings(&settings).is_err());
        }
        let settings = QuicSettings {
            handshake_timeout: Some(Duration::MAX),
            ..QuicSettings::default()
        };
        assert!(validate_runtime_settings(&settings).is_err());
        assert!(validate_runtime_settings(&QuicSettings::default()).is_ok());
    }

    #[test]
    fn invalid_alpn_is_reported_as_configuration_error() {
        let settings = QuicSettings {
            alpn: vec![vec![b'x'; 256]],
            ..QuicSettings::default()
        };
        let params =
            ConnectionParams::new_client(settings, None, Hooks::default());

        assert!(make_quiche_config(&params, false).is_err());
    }

    #[test]
    fn tls_hook_error_is_not_a_default_context_fallback() -> QuicResult<()> {
        struct FailingHook;
        impl crate::quic::ConnectionHook for FailingHook {
            fn create_custom_ssl_context_builder(
                &self, _settings: TlsCertificatePaths<'_>,
            ) -> QuicResult<Option<btls::ssl::SslContextBuilder>> {
                Err(std::io::Error::other("custom TLS context rejected").into())
            }
        }
        let params = ConnectionParams::new_server(
            QuicSettings::default(),
            TlsCertificatePaths {
                cert: "unused",
                private_key: "unused",
                kind: CertificateKind::X509,
            },
            Hooks {
                connection_hook: Some(std::sync::Arc::new(FailingHook)),
            },
        );
        let error = make_quiche_config(&params, false)
            .err()
            .ok_or("TLS hook failure was ignored")?;
        assert_eq!(error.to_string(), "custom TLS context rejected");
        Ok(())
    }

    #[cfg(not(feature = "rpk"))]
    #[test]
    fn raw_public_key_without_feature_is_unsupported() -> crate::QuicResult<()> {
        let tls = TlsCertificatePaths {
            cert: "unused-rpk-cert",
            private_key: "unused-rpk-key",
            kind: CertificateKind::RawPublicKey,
        };

        let Err(err) = quiche_config_with_tls(Some(tls)) else {
            return Err("RPK without the rpk feature must return an error".into());
        };

        let io_err = err
            .downcast_ref::<std::io::Error>()
            .ok_or("unsupported RPK error should be an io::Error")?;
        assert_eq!(io_err.kind(), std::io::ErrorKind::Unsupported);
        Ok(())
    }
}
