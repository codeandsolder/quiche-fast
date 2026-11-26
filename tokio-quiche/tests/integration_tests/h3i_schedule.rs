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

//! Integration tests for the shared h3i action scheduler and connection
//! summary.

use std::time::Duration;

use crate::fixtures::h3i_fixtures;
use crate::fixtures::start_server;
use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;
use h3i::client::connection_summary::CloseTriggerFrames;
use h3i::client::connection_summary::ConnectionSummary;
use h3i::frame::CloseTriggerFrame;
use h3i::frame::H3iFrame;
use h3i::quiche::h3::frame::Frame;
use h3i::quiche::ConnectionError;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn actions() -> Vec<Action> {
    vec![
        // Empty flushes must make progress without a peer packet.
        Action::FlushPackets,
        Action::FlushPackets,
        WaitType::WaitDuration(Duration::from_millis(5)).into(),
        WaitType::WaitDuration(Duration::from_millis(5)).into(),
        send_headers_frame(0, true, h3i_fixtures::default_headers()),
        Action::FlushPackets,
        WaitType::StreamEvent(StreamEvent {
            stream_id: 0,
            event_type: StreamEventType::Headers,
        })
        .into(),
        WaitType::StreamEvent(StreamEvent {
            stream_id: 0,
            event_type: StreamEventType::Finished,
        })
        .into(),
        send_headers_frame(4, true, h3i_fixtures::default_headers()),
        Action::FlushPackets,
    ]
}

fn close_error() -> ConnectionError {
    ConnectionError {
        is_app: true,
        error_code: 0x123,
        reason: b"custom close trigger".to_vec(),
    }
}

fn triggers() -> CloseTriggerFrames {
    CloseTriggerFrames::new_with_connection_close(
        vec![CloseTriggerFrame::new_with_comparator(4, |frame| {
            matches!(frame, H3iFrame::QuicheH3(Frame::Data { .. }))
        })],
        close_error(),
    )
}

fn check_summary(summary: &ConnectionSummary) {
    assert!(h3i_fixtures::received_status_code_on_stream(
        summary, 0, 200
    ));
    assert!(h3i_fixtures::received_status_code_on_stream(
        summary, 4, 200
    ));
    assert!(summary.stream_map.all_close_trigger_frames_seen());
    assert_eq!(
        summary.conn_close_details.local_error(),
        Some(&close_error())
    );
    assert!(!summary.conn_close_details.timed_out);
}

#[tokio::test]
async fn shared_scheduler_completes_waits_and_flushes_sync() -> TestResult {
    let (url, ..) = start_server()?;
    let mut config = h3i_fixtures::h3i_config(&url)?;
    config.idle_timeout = 15_000;
    let task = tokio::task::spawn_blocking(move || {
        h3i::client::sync_client::connect(config, actions(), Some(triggers()))
    });
    let summary = timeout(Duration::from_secs(5), task).await???;
    check_summary(&summary);
    Ok(())
}

#[tokio::test]
async fn async_close_trigger_does_not_require_polling_summary() -> TestResult {
    let (url, _, mut server_closed) = start_server()?;
    let mut config = h3i_fixtures::h3i_config(&url)?;
    config.idle_timeout = 15_000;
    let completion =
        h3i::client::async_client::connect(&config, actions(), Some(triggers()))
            .await?;
    // The server must observe the close before the caller polls completion.
    assert!(timeout(Duration::from_secs(5), server_closed.recv())
        .await?
        .is_some());
    let summary = timeout(Duration::from_secs(5), completion).await??;
    check_summary(&summary);
    Ok(())
}

#[tokio::test]
async fn async_empty_close_trigger_closes_without_a_request() -> TestResult {
    let (url, _, mut server_closed) = start_server()?;
    let mut config = h3i_fixtures::h3i_config(&url)?;
    config.idle_timeout = 15_000;
    let completion = h3i::client::async_client::connect(
        &config,
        Vec::new(),
        Some(CloseTriggerFrames::new_with_connection_close(
            Vec::new(),
            close_error(),
        )),
    )
    .await?;
    assert!(timeout(Duration::from_secs(5), server_closed.recv())
        .await?
        .is_some());
    let summary = timeout(Duration::from_secs(5), completion).await??;
    assert!(summary.stream_map.is_empty());
    assert!(summary.stream_map.all_close_trigger_frames_seen());
    assert_eq!(
        summary.conn_close_details.local_error(),
        Some(&close_error())
    );
    assert!(!summary.conn_close_details.timed_out);
    Ok(())
}
