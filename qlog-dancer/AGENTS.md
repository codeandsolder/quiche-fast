# qlog-dancer/

## OVERVIEW

Visualization/analysis tool for qlog and Chrome netlog files. Parses logs into a `Datastore`, extracts time-series into `SeriesStore`, renders PNG charts (native) or canvas plots (wasm). Outputs HTML/text reports with tabled summaries.

Dual-target: native CLI binary (`main.rs`) + wasm-bindgen web UI (`web.rs`, `#[cfg(target_arch = "wasm32")]`). `crate-type = ["lib", "cdylib"]` -- cdylib is for wasm.

## STRUCTURE

```
src/
  main.rs              CLI entry: parse args via AppConfig, render selected plots, emit report
  lib.rs               Public API: parse_log_file(), PacketType, type aliases
  web.rs               wasm-bindgen exports, canvas rendering, JS interop
  sqlog_stream.rs      Incremental JSON-SEQ framing/decoding shared by wasm and native tests
  config.rs            AppConfig (clap CLI + wasm config), plot toggles, colors
  datastore.rs         Datastore struct, log event handlers and netlog session reader
  seriesstore.rs       SeriesStore: extracts plot-ready time-series from Datastore
  wirefilter.rs        Event filtering via cloudflare/wirefilter-engine DSL
  request_stub.rs      Stub types for request-level data; preserves initial metadata across trailing HEADERS
  plots/               Chart rendering (plotters crate)
    mod.rs             PlotParameters, ChartSize, ClampParams, output type enums
    conn_overview.rs   Multi-panel connection overview (cwnd, bytes, rtt, streams)
    congestion_control.rs  CC-specific plot
    conn_flow_control.rs   Connection-level flow control
    packet_sent.rs     Packet-number vs time scatter
    packet_received.rs Received packet scatter
    stream_sparks.rs   Per-stream sparkline grids
    stream_multiplex.rs  Stream multiplexing timeline
    pending.rs         Pending data plot
    rtt.rs             RTT plot
    colors.rs          Color palettes
    minmax.rs          Axis range utilities
  reports/             Output reports
    mod.rs             report() dispatcher
    html.rs            HTML report generation (table_to_html)
    text.rs            Plain-text summary
    events.rs          Event-level report details
  trackers/            Stateful metric accumulators
    stream_buffer_tracker.rs  Per-stream buffer sizes
    stream_max_tracker.rs     Stream high-water marks
index.html, *.js, *.css   Web UI assets (crate root, non-standard location)
```

## WHERE TO LOOK

| Task | File |
|------|------|
| Add new plot type | `src/plots/` -- add module, wire into `main.rs` + `web.rs`; `plots/mod.rs::ChartConfig::chart_name()` centrally builds PNG/canvas metadata and optional PNG axis-limit suffixes |
| Update stream sparks | `src/plots/stream_sparks.rs`: `SparkOutputs<T>` is a typed 2×2 direction (download/upload) × domain (absolute/relative) grid. Use `try_map()` to initialize native bitmap and wasm canvas backends consistently; it stops on the first error. Marker drawing is iterator-based (no per-stream circle vector), and two-point request timing lines use stack arrays. `frame_series_for_vantage()` selects HTTP/2/HTTP/3 client/server streams. Keep shared row slots for upload-only and download-only streams, and preserve the HTTP/2 upload secondary send-window axis. `SparkCaption::for_each_row()` is the allocation-free source for client/server caption row offsets and propagates drawing errors |
| Update multiplex plots/colors | `src/plots/stream_multiplex.rs` traverses a reusable sorted, filtered `BTreeMap` request iterator rather than collecting request/frame-reference vectors; `request_data_frames()` selects RX for client or TX for server consistently across global bounds, data lanes, maxima and per-stream rows. In `src/plots/colors.rs`, `ColorCycle` borrows a validated nonempty palette and the default 100-color sequence is immutable static data, avoiding a palette heap allocation on each render. Preserve palette order and lane colors; both HTTP/2 and HTTP/3 filtering apply before row sizing. |
| Congestion and connection-flow charts | `src/plots/congestion_control.rs` groups equivalent Cubic/Reno and BBR states into shared RGB mappings; label rectangle right edges use checked `usize → i32` arithmetic, including the final inset. Plotters' positioned `Text` requires owned strings, so retain the `name.clone()` for state labels. `src/plots/conn_flow_control.rs` uses `ApplicationProto` by value to select independent HTTP/2 and HTTP/3 receive/window histories; its max calculation saturates at `u64::MAX`, and native/WASM chart paths share the renderer. Keep legend line segments stack-allocated. |
| Change parsed fields | `src/datastore.rs` -- all log-to-struct extraction. HTTP/2 + HTTP/3 inbound DATA share `record_netlog_received_data()` (only H2 adds connection cumulative); HTTP/2 outbound DATA uses `record_netlog_sent_h2_data()` and updates send-window credit. All checked counts and cumulative totals must be validated before any event-state mutation. `record_netlog_ack_gaps()` tracks sent/received ACK gaps separately; received gaps without preceding packet metadata stay in `PacketType::Unknown` rather than being dropped. Netlog received packet discontinuities must compare last-observed numbers **within** Initial, Handshake or Application Data space (0-RTT and 1-RTT share Application Data), stored in `NetlogPacketNumberProgress`; Unknown/Retry/VN cannot establish a space. QUIC event dispatch uses `record_netlog_received_quic_stream_frame()`, `record_netlog_received_packet_header()`, `record_netlog_sent_packet()` and `record_netlog_quic_stream_termination()`; termination direction is a typed enum, and nonexistent request streams must not be allocated merely for resets. H2 control events share `record_netlog_h2_window_update()` and `record_netlog_h2_stream_reset()` with typed sent/received direction: received WINDOW_UPDATE grants our send credit, sent WINDOW_UPDATE grants peer credit; invalid increments are ignored. See `netlog_tests` |
| HTTP/3 qlog event mapping | `src/datastore.rs::consume_qlog_h3_frame()` unifies created/parsed DATA, HEADERS and priority updates. Created-client and parsed-server HEADERS are **requests** (including method, host, path, priority and content-length); created-server and parsed-client HEADERS are **responses**. Only created-client/parsed-server PRIORITY_UPDATE events are recorded. Preserve the received-DATA series' client-vantage-only behavior until deliberately migrated with plotting tests. |
| Change log dispatch/parsing | `src/lib.rs` -- `parse_log_file()` routes to `parse_qlog_json()`, `parse_qlog_json_seq()`, `parse_netlog_json()`; each preserves format-specific trace identity and raw events |
| Add series for plotting | `src/seriesstore.rs` |
| Modify event filters | `src/wirefilter.rs` (wirefilter-engine DSL) |
| CLI args / config | `src/config.rs` (AppConfig, clap) |
| Wasm API surface | `src/web.rs` (`#[wasm_bindgen]` exports) |
| Report formatting | `src/reports/` -- `events.rs` renders QUIC and HTTP/3 frames directly into existing `String` buffers using `std::fmt::Write`, avoiding temporary allocations in the per-frame path; `text.rs::AckGapSession` streams netlog ACK gaps directly through a `Display` formatter, using `packet_sent` for received ACKs and `packet_received` for sent ACKs. Counts with no observed packets are `n/a`, not zero-percent or confirmed loss. `text.rs::SentPacketLine` streams the actual `PacketInfoStub.acked` state (`yes`, `no`, or `unknown`) through an allocation-free `Display` formatter; `None` is not confirmed loss |

## NOTES

- Native build requires system libs: **libexpat, freetype, fontconfig** (plotters SVG/bitmap backends).
- Wasm uses `plotters-canvas` backend -- canvas rendering, no system deps.
- `wirefilter-engine` pinned to specific git rev, not on crates.io.
- Log format detection is case-insensitive on the filename's final extension; parsing can retry between qlog JSON and JSON-SEQ where applicable.
- Native CLI numeric arguments are typed in `AppConfig::command()` and validated in `AppConfig::from_matches()`: `-s`/`--start`, `-e`/`--end` accept finite nonnegative `f64` with end >= start; `--stream-y-axis-max` and `--cwnd-y-axis-max` accept positive `u64`. The canonical dark-mode flag is `--dark-mode`; old underscore spellings are not retained.
- Browser JSON-SEQ parsing lives in `sqlog_stream.rs`: ASCII record separators delimit records (not network/file chunks). `process_chunk()` accepts arbitrary fragments, `finish_stream()` commits the EOF record, and errors propagate. `read_stream()` finishes automatically. Always add native tests for every-byte split positions and malformed/truncated data when changing this path.
- Browser datastore vantage point comes from the JSON-SEQ header, not a hard-coded server default. Reuse `Datastore::with_sqlog_reader_events` for consistent native and web interpretation.
- WASM `get_chart_info()` is fallible and serializes `u64` chart endpoints as JavaScript `BigInt`; the default serde-wasm-bindgen serializer rejects integers above JS `MAX_SAFE_INTEGER`. Keep exact interpolation/tooltip formatting in `canvas-math.mjs`, converting to `Number` only when passing zoom limits into the existing `f64` plotting interface. Native Node tests live in `tests/canvas_math.test.mjs` and run as part of the shared Stable WASM job.
- The browser's canvas interaction listeners are registered only once per element; mouse events must use explicit event parameters, not the deprecated global `event`.
- `getrandom/wasm_js` feature + `.cargo/config.toml` needed for wasm randomness.
- Web assets (`index.html`, `qlog-dancer-ui.js`, `qlog-dancer.css`) live in crate root, not `src/`.
