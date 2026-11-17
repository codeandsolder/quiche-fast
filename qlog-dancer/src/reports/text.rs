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

//! Reporting (tables etc.)

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;

use qlog::events::quic::QuicFrame;
use tabled::settings::location::ByColumnName;
use tabled::settings::object::Segment;
use tabled::settings::Alignment;
use tabled::settings::Modify;
use tabled::settings::Remove;
use tabled::settings::Style;
use tabled::Table;

use crate::config::AppConfig;
use crate::datastore::Datastore;
use crate::datastore::PacketInfoStub;
use crate::datastore::PrintStatsConfig;
use crate::request_stub::*;
use crate::stringify_last;
use crate::LogFileData;

pub fn request_timing_table(lf: &LogFileData, config: &AppConfig) -> Table {
    let mut table = Table::new(lf.datastore.http_requests.values());
    table.with(Modify::new(Segment::all()).with(Alignment::right()));

    if config.report_omit_upload {
        table
            .with(Remove::column(ByColumnName::new(CLIENT_CONTENT_LENGTH)))
            .with(Remove::column(ByColumnName::new(CLIENT_TRANSFERRED)))
            .with(Remove::column(ByColumnName::new(UPLOAD_TIME)))
            .with(Remove::column(ByColumnName::new(UPLOAD_RATE)));
    }

    match lf.datastore.vantage_point {
        crate::datastore::VantagePoint::Client => {
            table
                .with(Remove::column(ByColumnName::new(SERVER_RX_HDR_TX_HDR)))
                .with(Remove::column(ByColumnName::new(
                    SERVER_TX_HDR_TX_FIRST_HDR,
                )))
                .with(Remove::column(ByColumnName::new(
                    SERVER_TX_HDR_TX_LAST_HDR,
                )))
                .with(Remove::column(ByColumnName::new(
                    SERVER_TX_FIRST_DATA_TX_LAST_DATA,
                )));
        },

        crate::datastore::VantagePoint::Server => {
            // TODO:
        },
    }

    if config.report_omit_priorities {
        table
            .with(Remove::column(ByColumnName::new(CLIENT_PRI)))
            .with(Remove::column(ByColumnName::new(SERVER_PRI)));
    }

    if config.report_text_csv {
        let style = Style::empty().vertical(',');

        table.with(style);
    }

    table
}

pub fn print_stats(data_store: &Datastore, config: &PrintStatsConfig) {
    if config.rx_flow_control {
        print_rx_max_data_frames(data_store);
        print_rx_max_stream_data_frames(data_store);
    }

    if config.tx_flow_control {
        print_tx_max_data_frames(data_store);
        print_tx_max_stream_data_frames(data_store);
    }

    if config.reset_streams {
        print_tx_reset_stream_frames(data_store);
        print_rx_reset_stream_frames(data_store);
    }

    if config.tx_stream_frames {
        print_tx_stream_frames(data_store);
    }

    if config.stream_buffering {
        print_local_stream_buffer_reads(data_store);
        print_local_stream_buffer_writes(data_store);
        print_local_stream_buffer_dropped(data_store);
        print_stream_buffer(
            "local stream buffer user",
            &data_store.stream_buffer_user_tracker,
        );
        print_stream_buffer(
            "local stream buffer network",
            &data_store.stream_buffer_network_tracker,
        );
    }

    if config.packet_stats {
        print_sent_packet_stats(data_store);
    }
}

/// An absent ACK observation is unknown, not evidence that the packet was lost.
const fn ack_status_label(acked: Option<bool>) -> &'static str {
    match acked {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

/// Formatting directly to stdout retains constant additional memory even
/// when the datastore contains millions of sent packets.
struct SentPacketLine<'a> {
    number: u64,
    packet: &'a PacketInfoStub,
}

impl std::fmt::Display for SentPacketLine<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (length, payload_length) = self
            .packet
            .raw
            .as_ref()
            .map_or((None, None), |raw| (raw.length, raw.payload_length));
        let acked = ack_status_label(self.packet.acked);
        write!(
            formatter,
            "\tpkt_num={}, acked={acked}, length={length:?}, payload_length={payload_length:?}, ",
            self.number,
        )
    }
}

fn print_sent_packet_stats(data_store: &Datastore) {
    println!("### sent packets ###");
    for (packet_space, packets) in &data_store.packet_sent {
        println!("\t# packet space={packet_space:?}");

        for (number, packet) in packets {
            println!("{}", SentPacketLine {
                number: *number,
                packet
            });
        }
        println!();
    }
}

fn print_max_data_frames(label: &str, values: &[(f64, u64)]) {
    println!("### {label} MAX_DATA frames ###");
    match (values.first(), values.last()) {
        (Some(first), Some(last)) => println!(
            "    total_count={}, first={first:?}, last={last:?}",
            values.len(),
        ),
        _ => println!("    None"),
    }
}

fn print_rx_max_data_frames(data_store: &Datastore) {
    print_max_data_frames("received", &data_store.received_max_data);
}

fn print_tx_max_data_frames(data_store: &Datastore) {
    print_max_data_frames("sent", &data_store.sent_max_data);
}

fn print_rx_max_stream_data_frames(data_store: &Datastore) {
    println!("### received MAX_STREAM_DATA frames ###");
    if data_store
        .received_stream_max_data_tracker
        .per_stream
        .is_empty()
    {
        println!("    None")
    } else {
        for entry in &data_store.received_stream_max_data_tracker.per_stream {
            println!(
                "    stream={}, total_count={}, first={:?}, last={}",
                entry.0,
                entry.1.len(),
                entry.1.first(),
                stringify_last(entry.1)
            );
        }
    }
}

fn print_tx_max_stream_data_frames(data_store: &Datastore) {
    println!("### sent MAX_STREAM_DATA frames ###");
    if data_store
        .sent_stream_max_data_tracker
        .per_stream
        .is_empty()
    {
        println!("    None")
    } else {
        for entry in &data_store.sent_stream_max_data_tracker.per_stream {
            println!(
                "    stream={}, total_count={}, first={:?}, last={:?}",
                entry.0,
                entry.1.len(),
                entry.1.first(),
                entry.1.last()
            );
        }
    }
}

fn print_tx_reset_stream_frames(data_store: &Datastore) {
    println!("### sent RESET_STREAM frames ###");
    if data_store.sent_reset_stream.is_empty() {
        println!("    None")
    } else {
        for entry in &data_store.sent_reset_stream {
            println!(
                "    stream={}, total_count={}, first={:?}, last={:?}",
                entry.0,
                entry.1.len(),
                entry.1.first(),
                stringify_last(entry.1)
            );
        }
    }
}

fn print_rx_reset_stream_frames(data_store: &Datastore) {
    println!("### received RESET_STREAM frames ###");
    if data_store.received_reset_stream.is_empty() {
        println!("    None")
    } else {
        for entry in &data_store.received_reset_stream {
            println!(
                "    stream={}, total_count={}, first={:?}, last={:?}",
                entry.0,
                entry.1.len(),
                entry.1.first(),
                stringify_last(entry.1)
            );
        }
    }
}

fn print_stream_buffer(
    label: &str, tracker: &crate::trackers::StreamBufferTracker,
) {
    println!("### {label} ###");
    if tracker.per_stream.is_empty() {
        println!("    None");
        return;
    }
    for (stream_id, accesses) in &tracker.per_stream {
        match (accesses.first(), accesses.last()) {
            (Some((_, first)), Some((_, last))) => {
                println!(
                    "    stream={stream_id}, total_count={}, first=(offset={}, length={}), last=(offset={}, length={}), max_end={}",
                    accesses.len(),
                    first.offset,
                    first.length,
                    last.offset,
                    last.length,
                    tracker.get_stream_max(*stream_id).map_or_else(|| "n/a".to_string(), |maximum| maximum.to_string()),
                );
            },
            _ => println!("    stream={stream_id}, total_count=0, max_end=n/a"),
        }
    }
}

fn print_local_stream_buffer_reads(data_store: &Datastore) {
    print_stream_buffer(
        "local stream buffer reads",
        &data_store.stream_buffer_reads_tracker,
    );
}

fn print_local_stream_buffer_writes(data_store: &Datastore) {
    print_stream_buffer(
        "local stream buffer writes",
        &data_store.stream_buffer_writes_tracker,
    );
}

fn print_local_stream_buffer_dropped(data_store: &Datastore) {
    print_stream_buffer(
        "local stream buffer dropped",
        &data_store.stream_buffer_dropped_tracker,
    );
}

/// Return the greatest end offset among STREAM frames, not the end of whichever
/// frame happens to be last in the log (events may be out of order).
/// An unrepresentable offset is reported explicitly rather than wrapped.
fn max_stream_frame_end(frames: &[(f64, QuicFrame)]) -> Result<Option<u64>, ()> {
    frames
        .iter()
        .try_fold(None, |maximum: Option<u64>, (_, frame)| match frame {
            QuicFrame::Stream { offset, raw, .. } => {
                let length = raw
                    .as_ref()
                    .and_then(|info| info.payload_length)
                    .unwrap_or_default();
                let end =
                    offset.unwrap_or_default().checked_add(length).ok_or(())?;
                Ok(Some(maximum.map_or(end, |current| current.max(end))))
            },
            _ => Ok(maximum),
        })
}

fn print_tx_stream_frames(data_store: &Datastore) {
    println!("### sent STREAM frames ###");
    if data_store.sent_stream_frames.is_empty() {
        println!("    None");
    } else {
        for (stream_id, frames) in &data_store.sent_stream_frames {
            let max_end = match max_stream_frame_end(frames) {
                Ok(Some(value)) => value.to_string(),
                Ok(None) => "n/a".to_string(),
                Err(()) => "overflow".to_string(),
            };
            println!(
                "    stream={stream_id}, total_count={}, first={:?}, last={:?}, max_end={max_end}",
                frames.len(), frames.first(), stringify_last(frames),
            );
        }
    }
}

pub fn print_flow_control(data: &[LogFileData]) {
    // TODO make this a proper table
    println!("================");
    println!("flow control stuff");
    println!("================");
    for lf in data {
        println!(
            "Session={}, host={}",
            lf.datastore.session_id.unwrap_or(-1),
            lf.datastore
                .host
                .clone()
                .unwrap_or("ERROR UNKNOWN".to_string())
        );

        println!("  Initial Client connection window, Initial Client Bidi Local Stream Window");
        println!(
            "  {},{}",
            lf.datastore.client_quic_tps.initial_max_data.unwrap_or(0),
            lf.datastore
                .client_quic_tps
                .initial_max_stream_data_bidi_local
                .unwrap_or(0)
        );

        for (stream_id, points) in
            &lf.datastore.netlog_quic_client_side_window_updates
        {
            println!("  Stream {} flow control updates", stream_id);
            println!("    Time, Value");

            for (time, val) in points {
                println!("    {},{}", time, val);
            }
        }
    }
}

/// Percentage of ACK-gap observations relative to the number of logged
/// packets in the corresponding direction. This is not a loss probability.
///
/// Use integer basis points so the value is exact even for counts above the
/// 53-bit floating-point integer range; round half up to two decimals.
fn ack_gap_percentage(gaps: usize, observed: usize) -> String {
    if observed == 0 {
        return "n/a".to_owned();
    }

    let denominator = observed as u128;
    let hundredths = ((gaps as u128) * 10_000 + denominator / 2) / denominator;
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

fn append_ack_gap_section(
    output: &mut impl std::fmt::Write, heading: &str,
    missing: &BTreeMap<crate::PacketType, BTreeSet<u64>>,
    observed: &HashMap<crate::PacketType, BTreeMap<u64, PacketInfoStub>>,
) -> std::fmt::Result {
    if !missing.values().any(|numbers| !numbers.is_empty()) {
        return Ok(());
    }

    writeln!(output, "  {heading}")?;
    writeln!(
        output,
        "    Packet type, Observed packets, ACK gaps, ACK gaps / observed (%), Missing packet numbers"
    )?;

    for (packet_type, missing_numbers) in missing {
        if missing_numbers.is_empty() {
            continue;
        }

        // No packet-map entry is different from zero missing ACK numbers:
        // preserve the observation, but report an undefined ratio.
        let observed_count = observed.get(packet_type).map_or(0, BTreeMap::len);
        let percentage =
            ack_gap_percentage(missing_numbers.len(), observed_count);
        writeln!(
            output,
            "    {packet_type:?}, {observed_count}, {}, {percentage}, {missing_numbers:?}",
            missing_numbers.len(),
        )?;
    }
    writeln!(output)
}

/// Format an ACK-gap session directly to the output formatter. The CLI never
/// accumulates the packet-number sets into a second full-report buffer.
struct AckGapSession<'a>(&'a Datastore);

impl std::fmt::Display for AckGapSession<'_> {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = self.0;
        let sent_gaps = &data.netlog_ack_received_missing_packet;
        let received_gaps = &data.netlog_ack_sent_missing_packet;

        if !sent_gaps.values().any(|numbers| !numbers.is_empty()) &&
            !received_gaps.values().any(|numbers| !numbers.is_empty())
        {
            return Ok(());
        }

        writeln!(
            output,
            "Session={}, host={}",
            data.session_id.unwrap_or(-1),
            data.host.as_deref().unwrap_or("ERROR UNKNOWN")
        )?;
        writeln!(
            output,
            "  ACK gaps are not confirmed loss; netlog packet-space attribution may be approximate."
        )?;

        // ACKs from the peer describe packets we transmitted; ACKs we sent
        // describe packets transmitted by the peer.
        append_ack_gap_section(
            output,
            "Packets sent, missing from received ACKs",
            sent_gaps,
            &data.packet_sent,
        )?;
        append_ack_gap_section(
            output,
            "Packets received, missing from sent ACKs",
            received_gaps,
            &data.packet_received,
        )
    }
}

/// Print the Chrome netlog ACK-gap report across all parsed sessions.
///
/// ACK gaps may reflect delayed ACKs, reordering, or incomplete logging rather
/// than confirmed packet loss. The percentage is relative to logged packets
/// in the respective direction, not an estimate of true connection loss.
pub fn print_packet_loss(data: &[LogFileData]) {
    println!("================");
    println!("QUIC ACK gaps");
    println!("================");

    for session in data {
        print!("{}", AckGapSession(&session.datastore));
    }
    println!();
}

#[cfg(test)]
mod report_safety_tests {
    use super::*;
    use qlog::events::quic::QuicFrame;

    fn stream(offset: u64, length: u64) -> QuicFrame {
        QuicFrame::Stream {
            stream_id: 1,
            offset: Some(offset),
            fin: None,
            raw: Some(Box::new(qlog::events::RawInfo {
                payload_length: Some(length),
                ..Default::default()
            })),
        }
    }

    fn observed_packet(
        packet_type: crate::PacketType, number: u64,
    ) -> PacketInfoStub {
        PacketInfoStub {
            acked: None,
            raw: None,
            created_time: 0.0,
            send_at_time: None,
            ty: packet_type,
            number,
        }
    }

    #[test]
    fn sent_packet_stats_use_the_recorded_ack_state() {
        let mut datastore = Datastore::default();
        let packet_type = crate::PacketType::OneRtt;
        let mut packets = BTreeMap::new();

        for (number, acked) in [(10, Some(true)), (11, None), (12, Some(false))] {
            let mut packet = observed_packet(packet_type, number);
            packet.acked = acked;
            if number == 10 {
                packet.raw = Some(qlog::events::RawInfo {
                    length: Some(128),
                    payload_length: Some(100),
                    ..Default::default()
                });
            }
            packets.insert(number, packet);
        }
        datastore.packet_sent.insert(packet_type, packets);

        let lines: Vec<_> = datastore.packet_sent[&packet_type]
            .iter()
            .map(|(number, packet)| {
                SentPacketLine {
                    number: *number,
                    packet,
                }
                .to_string()
            })
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0],
            "\tpkt_num=10, acked=yes, length=Some(128), payload_length=Some(100), "
        );
        assert_eq!(
            lines[1],
            "\tpkt_num=11, acked=unknown, length=None, payload_length=None, "
        );
        assert_eq!(
            lines[2],
            "\tpkt_num=12, acked=no, length=None, payload_length=None, "
        );
    }

    #[test]
    fn ack_gap_percentages_are_exact_and_handle_empty_denominators() {
        assert_eq!(ack_gap_percentage(1, 0), "n/a");
        assert_eq!(ack_gap_percentage(0, 0), "n/a");
        assert_eq!(ack_gap_percentage(0, 8), "0.00");
        assert_eq!(ack_gap_percentage(1, 3), "33.33");
        assert_eq!(ack_gap_percentage(2, 3), "66.67");
        assert_eq!(ack_gap_percentage(1, 6), "16.67");
        assert_eq!(ack_gap_percentage(1, 20_000), "0.01");
        assert_eq!(ack_gap_percentage(1, 30_000), "0.00");
        assert_eq!(ack_gap_percentage(3, 2), "150.00");
        // Neither multiplication nor rounding should go through f64.
        assert_eq!(ack_gap_percentage(usize::MAX, usize::MAX), "100.00");
        assert_eq!(ack_gap_percentage(usize::MAX - 1, usize::MAX), "100.00");
    }

    #[test]
    fn report_uses_sent_packets_for_received_acks_and_received_for_sent_acks() {
        let packet_type = crate::PacketType::OneRtt;
        let mut datastore = Datastore {
            session_id: Some(7),
            host: Some("example.test".to_owned()),
            ..Default::default()
        };
        datastore.packet_sent.insert(
            packet_type,
            (0..8)
                .map(|number| (number, observed_packet(packet_type, number)))
                .collect(),
        );
        datastore.packet_received.insert(
            packet_type,
            (0..2)
                .map(|number| (number, observed_packet(packet_type, number)))
                .collect(),
        );
        datastore
            .netlog_ack_received_missing_packet
            .insert(packet_type, BTreeSet::from([2, 3]));
        datastore
            .netlog_ack_sent_missing_packet
            .insert(packet_type, BTreeSet::from([1]));

        let report = AckGapSession(&datastore).to_string();
        assert!(report.contains("Session=7, host=example.test"));
        assert!(report.contains("Packets sent, missing from received ACKs"));
        assert!(report.contains("    OneRtt, 8, 2, 25.00, {2, 3}"));
        assert!(report.contains("Packets received, missing from sent ACKs"));
        assert!(report.contains("    OneRtt, 2, 1, 50.00, {1}"));
        assert!(report.contains("not confirmed loss"));
    }

    #[test]
    fn report_retains_unknown_gap_spaces_even_without_observed_packets() {
        let mut datastore = Datastore::default();
        datastore
            .netlog_ack_sent_missing_packet
            .insert(crate::PacketType::Unknown, BTreeSet::from([u64::MAX]));

        let report = AckGapSession(&datastore).to_string();
        assert!(report.contains("Session=-1, host=ERROR UNKNOWN"));
        assert!(report.contains("Packets received, missing from sent ACKs"));
        assert!(
            report.contains(&format!("    Unknown, 0, 1, n/a, {{{}}}", u64::MAX))
        );
        assert!(!report.contains("Packets sent, missing from received ACKs"));
        assert!(!report.contains("NaN"));
        assert!(!report.contains("inf"));
    }

    #[test]
    fn report_suppresses_only_empty_ack_gap_sets() {
        let mut datastore = Datastore::default();
        datastore
            .netlog_ack_received_missing_packet
            .insert(crate::PacketType::Initial, BTreeSet::new());
        assert_eq!(AckGapSession(&datastore).to_string(), "");

        datastore
            .netlog_ack_received_missing_packet
            .insert(crate::PacketType::Handshake, BTreeSet::from([99]));
        let report = AckGapSession(&datastore).to_string();
        assert!(report.contains("    Handshake, 0, 1, n/a, {99}"));
        assert!(!report.contains("    Initial,"));
    }

    #[test]
    fn stream_frame_end_uses_highest_valid_offset_in_any_order() {
        assert_eq!(max_stream_frame_end(&[]), Ok(None));
        let frames = vec![
            (3.0, stream(900, 100)),
            (1.0, stream(0, 50)),
            (2.0, stream(50, 70)),
        ];
        assert_eq!(max_stream_frame_end(&frames), Ok(Some(1000)));
        assert_eq!(
            max_stream_frame_end(&[(1.0, stream(u64::MAX - 2, 2))]),
            Ok(Some(u64::MAX))
        );
    }

    #[test]
    fn stream_frame_end_rejects_overflow_in_any_frame() {
        let frames = vec![(1.0, stream(u64::MAX, 2)), (2.0, stream(0, 30))];
        assert_eq!(max_stream_frame_end(&frames), Err(()));
    }
}
