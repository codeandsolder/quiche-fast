// Copyright (C) 2021, Cloudflare, Inc.
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

use crate::events::EventData;
use crate::events::EventImportance;
use crate::events::EventType;
use crate::events::Eventable;
use crate::events::ExData;

/// Controls the time precisions of events.
///
/// Times are always logged in units of whole milliseconds with optional
/// precision, determining the number of decimal places output by the
/// serializer.
#[allow(
    clippy::enum_variant_names,
    reason = "Variant names are part of the established public qlog API"
)]
pub enum EventTimePrecision {
    /// Logging may contain 1 decimal place to ensure float serialization e.g.,
    /// 1.0, 2.0,
    MilliSeconds,
    /// Logged up to 3 decimal places e.g., 1.234, 2.001
    MicroSeconds,
    /// Logged up to 6 decimal places e.g., 1.234567, 2.001001
    NanoSeconds,
}

/// Converts a [`Duration`] to milliseconds as `f64` using the requested
/// precision variant.
#[expect(
    clippy::cast_precision_loss,
    reason = "qlog timestamps are f64, so converting integer duration units necessarily loses precision for extremely large durations"
)]
fn duration_to_millis(
    dur: std::time::Duration, precision: &EventTimePrecision,
) -> f64 {
    match precision {
        EventTimePrecision::MilliSeconds => dur.as_millis() as f64,
        EventTimePrecision::MicroSeconds => dur.as_micros() as f64 / 1_000.0,
        EventTimePrecision::NanoSeconds => dur.as_nanos() as f64 / 1_000_000.0,
    }
}

/// Computes elapsed time in milliseconds since `start`, based on the provided
/// `precision`. In test builds, always returns 0.0 for deterministic output.
fn elapsed_millis(
    start: std::time::Instant, now: std::time::Instant,
    precision: &EventTimePrecision,
) -> f64 {
    if cfg!(test) {
        return 0.0;
    }

    let dur = now.saturating_duration_since(start);
    duration_to_millis(dur, precision)
}

use super::Error;
use super::Event;
use super::QlogSeq;
use super::Result;
use super::Serialize;
use super::TraceSeq;
use super::QLOGFILESEQ_URI;

#[derive(PartialEq, Eq, Debug)]
pub enum StreamerState {
    Initial,
    Ready,
    Finished,
}

/// Streaming JSON-SEQ qlog writer.
///
/// Owns the qlog header and target writer and appends events after `start_log`.
pub struct QlogStreamer {
    start_time: std::time::Instant,
    writer: Box<dyn std::io::Write + Send + Sync>,
    qlog: QlogSeq,
    state: StreamerState,
    log_level: EventImportance,
    time_precision: EventTimePrecision,
}

impl QlogStreamer {
    /// Creates a [`QlogStreamer`] object.
    ///
    /// It owns a [`QlogSeq`] object that contains the provided [`TraceSeq`]
    /// containing [Event]s.
    ///
    /// All serialization will be written to the provided [`Write`] using the
    /// JSON-SEQ format.
    ///
    /// [`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[must_use]
    pub fn new(
        title: Option<String>, description: Option<String>,
        start_time: std::time::Instant, trace: TraceSeq,
        log_level: EventImportance, time_precision: EventTimePrecision,
        writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Self {
        let qlog = QlogSeq {
            file_schema: QLOGFILESEQ_URI.to_string(),
            serialization_format: "JSON-SEQ".to_string(),
            title,
            description,
            trace,
        };

        Self {
            start_time,
            writer,
            qlog,
            state: StreamerState::Initial,
            log_level,
            time_precision,
        }
    }

    /// Starts qlog streaming serialization.
    ///
    /// This writes out the JSON-SEQ-serialized form of all initial qlog
    /// information. [Event]s are separately appended using [`add_event()`],
    /// [`add_event_with_instant()`], [`add_event_now()`],
    /// [`add_event_data_with_instant()`], or [`add_event_data_now()`].
    ///
    /// [add_event()]: #method.add_event
    /// [add_event_with_instant()]: #method.add_event_with_instant
    /// [add_event_now()]: #method.add_event_now
    /// [add_event_data_with_instant()]: #method.add_event_data_with_instant
    /// [add_event_data_now()]: #method.add_event_data_now
    ///
    /// # Errors
    /// Returns an error if logging already started or header serialization or
    /// I/O fails.
    pub fn start_log(&mut self) -> Result<()> {
        if self.state != StreamerState::Initial {
            return Err(Error::Done);
        }

        self.writer.as_mut().write_all(b"")?;
        serde_json::to_writer(self.writer.as_mut(), &self.qlog)
            .map_err(|_| Error::Done)?;
        self.writer.as_mut().write_all(b"\n")?;

        self.state = StreamerState::Ready;

        Ok(())
    }

    /// Finishes qlog streaming serialization.
    ///
    /// After this is called, no more serialization will occur.
    ///
    /// # Errors
    /// Returns an error if logging is not active or flushing the writer fails.
    pub fn finish_log(&mut self) -> Result<()> {
        if self.state == StreamerState::Initial ||
            self.state == StreamerState::Finished
        {
            return Err(Error::InvalidState);
        }

        self.state = StreamerState::Finished;

        self.writer.as_mut().flush()?;

        Ok(())
    }

    /// Writes a serializable to a JSON-SEQ record using
    /// [`std::time::Instant::now()`].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_now<E: Serialize + Eventable>(
        &mut self, event: E,
    ) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_with_instant(event, now)
    }

    /// Writes a serializable to a pretty-printed JSON-SEQ record using
    /// [`std::time::Instant::now()`].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_now_pretty<E: Serialize + Eventable>(
        &mut self, event: E,
    ) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_with_instant_pretty(event, now)
    }

    /// Writes a serializable to a JSON-SEQ record using the provided
    /// [`std::time::Instant`].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_with_instant<E: Serialize + Eventable>(
        &mut self, event: E, now: std::time::Instant,
    ) -> Result<()> {
        self.event_with_instant(event, now, false)
    }

    /// Writes a serializable to a pretty-printed JSON-SEQ record using the
    /// provided [`std::time::Instant`].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_with_instant_pretty<E: Serialize + Eventable>(
        &mut self, event: E, now: std::time::Instant,
    ) -> Result<()> {
        self.event_with_instant(event, now, true)
    }

    fn event_with_instant<E: Serialize + Eventable>(
        &mut self, mut event: E, now: std::time::Instant, pretty: bool,
    ) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        if !event.importance().is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        event.set_time(elapsed_millis(
            self.start_time,
            now,
            &self.time_precision,
        ));

        if pretty {
            self.add_event_pretty(event)
        } else {
            self.add_event(event)
        }
    }

    /// Writes an [Event] based on the provided [`EventData`] to a JSON-SEQ
    /// record at time [`std::time::Instant::now()`].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_data_now(&mut self, event_data: EventData) -> Result<()> {
        self.add_event_data_ex_now(event_data, ExData::new())
    }

    /// Writes an [Event] based on the provided [`EventData`] to a
    /// pretty-printed JSON-SEQ record at time
    /// [`std::time::Instant::now()`].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_data_now_pretty(
        &mut self, event_data: EventData,
    ) -> Result<()> {
        self.add_event_data_ex_now_pretty(event_data, ExData::new())
    }

    /// Writes an [Event] based on the provided [`EventData`] and [`ExData`] to
    /// a JSON-SEQ record at time [`std::time::Instant::now()`].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_data_ex_now(
        &mut self, event_data: EventData, ex_data: ExData,
    ) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_data_ex_with_instant(event_data, ex_data, now)
    }

    /// Writes an [Event] based on the provided [`EventData`] and [`ExData`] to
    /// a pretty-printed JSON-SEQ record at time
    /// [`std::time::Instant::now()`].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_data_ex_now_pretty(
        &mut self, event_data: EventData, ex_data: ExData,
    ) -> Result<()> {
        let now = std::time::Instant::now();

        self.add_event_data_ex_with_instant_pretty(event_data, ex_data, now)
    }

    /// Writes an [Event] based on the provided [`EventData`] and
    /// [`std::time::Instant`] to a JSON-SEQ record.
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_data_with_instant(
        &mut self, event_data: EventData, now: std::time::Instant,
    ) -> Result<()> {
        self.add_event_data_ex_with_instant(event_data, ExData::new(), now)
    }

    /// Writes an [Event] based on the provided [`EventData`] and
    /// [`std::time::Instant`] to a pretty-printed JSON-SEQ record.
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_data_with_instant_pretty(
        &mut self, event_data: EventData, now: std::time::Instant,
    ) -> Result<()> {
        self.add_event_data_ex_with_instant_pretty(event_data, ExData::new(), now)
    }

    /// Writes an [Event] based on the provided [`EventData`], [`ExData`], and
    /// [`std::time::Instant`] to a JSON-SEQ record.
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_data_ex_with_instant(
        &mut self, event_data: EventData, ex_data: ExData,
        now: std::time::Instant,
    ) -> Result<()> {
        self.event_data_ex_with_instant(event_data, ex_data, now, false)
    }

    // Writes an [Event] based on the provided [EventData], [ExData], and
    /// [`std::time::Instant`] to a pretty-printed JSON-SEQ record.
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    pub fn add_event_data_ex_with_instant_pretty(
        &mut self, event_data: EventData, ex_data: ExData,
        now: std::time::Instant,
    ) -> Result<()> {
        self.event_data_ex_with_instant(event_data, ex_data, now, true)
    }

    fn event_data_ex_with_instant(
        &mut self, event_data: EventData, ex_data: ExData,
        now: std::time::Instant, pretty: bool,
    ) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        let ty = EventType::from(&event_data);
        if !EventImportance::from(ty).is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        let event = Event::with_time_ex(
            elapsed_millis(self.start_time, now, &self.time_precision),
            event_data,
            ex_data,
        );

        if pretty {
            self.add_event_pretty(event)
        } else {
            self.add_event(event)
        }
    }

    /// Writes a JSON-SEQ-serialized [Event] using the provided [Event].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Preserve the established public API that takes ownership of the event while serialization borrows it internally"
    )]
    pub fn add_event<E: Serialize + Eventable>(
        &mut self, event: E,
    ) -> Result<()> {
        self.write_event(&event, false)
    }

    /// Writes a pretty-printed JSON-SEQ-serialized [Event] using the provided
    /// [Event].
    ///
    /// # Errors
    /// Returns an error for invalid state, filtered events, serialization
    /// failure, or I/O failure.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Preserve the established public API that takes ownership of the event while serialization borrows it internally"
    )]
    pub fn add_event_pretty<E: Serialize + Eventable>(
        &mut self, event: E,
    ) -> Result<()> {
        self.write_event(&event, true)
    }

    /// Writes a JSON-SEQ-serialized [Event] using the provided [Event].
    fn write_event<E: Serialize + Eventable>(
        &mut self, event: &E, pretty: bool,
    ) -> Result<()> {
        if self.state != StreamerState::Ready {
            return Err(Error::InvalidState);
        }

        if !event.importance().is_contained_in(&self.log_level) {
            return Err(Error::Done);
        }

        self.writer.as_mut().write_all(b"")?;
        if pretty {
            serde_json::to_writer_pretty(self.writer.as_mut(), event)
                .map_err(|_| Error::Done)?;
        } else {
            serde_json::to_writer(self.writer.as_mut(), event)
                .map_err(|_| Error::Done)?;
        }
        self.writer.as_mut().write_all(b"\n")?;

        Ok(())
    }

    /// Returns the writer.
    #[expect(
        clippy::borrowed_box,
        reason = "Preserve the established public writer accessor type during the strict-gate migration"
    )]
    #[must_use]
    pub fn writer(&self) -> &Box<dyn std::io::Write + Send + Sync> {
        &self.writer
    }

    #[must_use]
    pub const fn start_time(&self) -> std::time::Instant {
        self.start_time
    }
}

impl Drop for QlogStreamer {
    fn drop(&mut self) {
        let _ = self.finish_log();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;
    use crate::events::quic;
    use crate::events::quic::QuicFrame;
    use crate::events::RawInfo;
    use crate::testing::*;

    use serde_json::json;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[derive(Clone)]
    struct CaptureWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| {
                    io::Error::other("capture writer mutex was poisoned")
                })?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn capture_writer(
    ) -> (Box<dyn std::io::Write + Send + Sync>, Arc<Mutex<Vec<u8>>>) {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = CaptureWriter {
            bytes: Arc::clone(&bytes),
        };
        (Box::new(writer), bytes)
    }

    fn captured_string(
        bytes: &Arc<Mutex<Vec<u8>>>,
    ) -> std::result::Result<String, Box<dyn std::error::Error>> {
        let bytes = bytes
            .lock()
            .map_err(|_| io::Error::other("capture writer mutex was poisoned"))?;
        Ok(std::str::from_utf8(&bytes)?.to_owned())
    }

    #[test]
    fn serialization_states() -> TestResult {
        let (writer, captured) = capture_writer();

        let trace = make_trace_seq();
        let pkt_hdr = make_pkt_hdr(quic::PacketType::Handshake);
        let raw = Some(RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        });

        let frame1 = QuicFrame::Stream {
            stream_id: 40,
            offset: Some(40),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(400),
                data: None,
            })),
            fin: Some(true),
        };

        let event_data1 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(vec![frame1]),
            raw: raw.clone(),
            ..Default::default()
        });

        let ev1 = Event::with_time(0.0, event_data1);

        let frame2 = QuicFrame::Stream {
            stream_id: 0,
            offset: Some(0),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(100),
                data: None,
            })),
            fin: Some(true),
        };

        let frame3 = QuicFrame::Stream {
            stream_id: 0,
            offset: Some(0),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(100),
                data: None,
            })),
            fin: Some(true),
        };

        let event_data2 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(vec![frame2]),
            raw: raw.clone(),
            ..Default::default()
        });

        let ev2 = Event::with_time(0.0, event_data2);

        let event_data3 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr,
            frames: Some(vec![frame3]),
            stateless_reset_token: Some(Box::new("reset_token".to_string())),
            raw,
            ..Default::default()
        });

        let ev3 = Event::with_time(0.0, event_data3);

        let mut s = QlogStreamer::new(
            Some("title".to_string()),
            Some("description".to_string()),
            std::time::Instant::now(),
            trace,
            EventImportance::Base,
            EventTimePrecision::NanoSeconds,
            writer,
        );

        // Before the log is started all other operations should fail.
        assert!(matches!(s.add_event(ev2.clone()), Err(Error::InvalidState)));
        assert!(matches!(s.finish_log(), Err(Error::InvalidState)));

        // Start log and add a simple event.
        assert!(matches!(s.start_log(), Ok(())));
        assert!(matches!(s.add_event(ev1), Ok(())));

        // Add some more events.
        assert!(matches!(s.add_event(ev2), Ok(())));
        assert!(matches!(s.add_event(ev3.clone()), Ok(())));

        // Adding an event with an external time should work too.
        // For tests, it will resolve to 0 but we care about proving the API
        // here, not timing specifics.
        let now = std::time::Instant::now();

        assert!(matches!(s.add_event_with_instant(ev3, now), Ok(())));

        assert!(matches!(s.finish_log(), Ok(())));

        let log_string = r#"{"file_schema":"urn:ietf:params:qlog:file:sequential","serialization_format":"JSON-SEQ","title":"title","description":"description","trace":{"title":"Quiche qlog trace","description":"Quiche qlog trace description","vantage_point":{"type":"server"},"event_schemas":[]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":40,"offset":40,"fin":true,"raw":{"payload_length":400}}]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"fin":true,"raw":{"payload_length":100}}]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"stateless_reset_token":"reset_token","raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"fin":true,"raw":{"payload_length":100}}]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"stateless_reset_token":"reset_token","raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":0,"offset":0,"fin":true,"raw":{"payload_length":100}}]}}
"#;

        let written_string = captured_string(&captured)?;

        pretty_assertions::assert_eq!(log_string, written_string);

        Ok(())
    }

    #[test]
    fn stream_json_event() -> TestResult {
        let data = json!({"foo": "Bar", "hello": 123});
        let ev = crate::events::JsonEvent {
            time: 0.0,
            importance: EventImportance::Core,
            name: "jsonevent:sample".into(),
            data,
        };

        let (writer, captured) = capture_writer();

        let trace = make_trace_seq();

        let mut s = QlogStreamer::new(
            Some("title".to_string()),
            Some("description".to_string()),
            std::time::Instant::now(),
            trace,
            EventImportance::Base,
            EventTimePrecision::NanoSeconds,
            writer,
        );

        assert!(matches!(s.start_log(), Ok(())));
        assert!(matches!(s.add_event(ev), Ok(())));
        assert!(matches!(s.finish_log(), Ok(())));

        let log_string = r#"{"file_schema":"urn:ietf:params:qlog:file:sequential","serialization_format":"JSON-SEQ","title":"title","description":"description","trace":{"title":"Quiche qlog trace","description":"Quiche qlog trace description","vantage_point":{"type":"server"},"event_schemas":[]}}
{"time":0.0,"name":"jsonevent:sample","data":{"foo":"Bar","hello":123}}
"#;

        let written_string = captured_string(&captured)?;

        pretty_assertions::assert_eq!(log_string, written_string);

        Ok(())
    }

    #[test]
    fn stream_data_ex() -> TestResult {
        let (writer, captured) = capture_writer();

        let trace = make_trace_seq();
        let pkt_hdr = make_pkt_hdr(quic::PacketType::Handshake);
        let raw = Some(RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        });

        let frame1 = QuicFrame::Stream {
            stream_id: 40,
            offset: Some(40),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(400),
                data: None,
            })),
            fin: Some(true),
        };

        let event_data1 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(vec![frame1]),
            raw: raw.clone(),
            ..Default::default()
        });
        let j1 = json!({"foo": "Bar", "hello": 123});
        let j2 = json!({"baz": [1,2,3,4]});
        let mut ex_data = BTreeMap::new();
        ex_data.insert("first".to_string(), j1);
        ex_data.insert("second".to_string(), j2);

        let ev1 = Event::with_time_ex(0.0, event_data1, ex_data);

        let frame2 = QuicFrame::Stream {
            stream_id: 1,
            offset: Some(0),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(100),
                data: None,
            })),
            fin: Some(true),
        };

        let event_data2 = EventData::QuicPacketSent(quic::PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(vec![frame2]),
            raw: raw.clone(),
            ..Default::default()
        });

        let ev2 = Event::with_time(0.0, event_data2);

        let mut s = QlogStreamer::new(
            Some("title".to_string()),
            Some("description".to_string()),
            std::time::Instant::now(),
            trace,
            EventImportance::Base,
            EventTimePrecision::NanoSeconds,
            writer,
        );

        assert!(matches!(s.start_log(), Ok(())));
        assert!(matches!(s.add_event(ev1), Ok(())));
        assert!(matches!(s.add_event(ev2), Ok(())));
        assert!(matches!(s.finish_log(), Ok(())));

        let log_string = r#"{"file_schema":"urn:ietf:params:qlog:file:sequential","serialization_format":"JSON-SEQ","title":"title","description":"description","trace":{"title":"Quiche qlog trace","description":"Quiche qlog trace description","vantage_point":{"type":"server"},"event_schemas":[]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":40,"offset":40,"fin":true,"raw":{"payload_length":400}}]},"first":{"foo":"Bar","hello":123},"second":{"baz":[1,2,3,4]}}
{"time":0.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":0,"version":"1","scil":8,"dcil":8,"scid":"7e37e4dcc6682da8","dcid":"36ce104eee50101c"},"raw":{"length":1251,"payload_length":1224},"frames":[{"frame_type":"stream","stream_id":1,"offset":0,"fin":true,"raw":{"payload_length":100}}]}}
"#;

        let written_string = captured_string(&captured)?;

        pretty_assertions::assert_eq!(log_string, written_string);

        Ok(())
    }

    #[test]
    fn elapsed_millis_precision() {
        let dur = std::time::Duration::from_nanos(1_234_567);
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::MilliSeconds),
            1.0
        );
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::MicroSeconds),
            1.234_000
        );
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::NanoSeconds),
            1.234_567
        );
    }

    #[test]
    fn elapsed_millis_zero_duration_all_precisions() {
        let dur = std::time::Duration::from_secs(0);
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::MilliSeconds),
            0.0
        );
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::MicroSeconds),
            0.0
        );
        assert_eq!(
            duration_to_millis(dur, &EventTimePrecision::NanoSeconds),
            0.0
        );
    }
}
