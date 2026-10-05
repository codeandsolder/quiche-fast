# Downstream performance validation with usque

`quiche-fast` is performance-sensitive in ways that are difficult to capture with a library-only microbenchmark. A change can reduce instructions inside quiche while changing syscall frequency, packet pacing, wakeups, buffering, or kernel work.

For that reason, the September–October 2026 optimization campaign used the full `usque-rs-fast -> quiche-fast -> tun-rs-fast` stack as a downstream validation harness.

The canonical methodology and campaign history live in:

- https://github.com/codeandsolder/usque-rs-fast/blob/main/docs/BENCHMARKING.md
- https://github.com/codeandsolder/usque-rs-fast/blob/main/docs/REJECTED_OPTIMIZATIONS.md — grep-friendly ledger of rejected, neutral, superseded, and deferred candidates across all three layers.

This page records the quiche-specific lessons so they are visible to someone working in this repository. Before starting an apparently obvious hot-path optimization, search the rejected-optimization ledger first; many attractive profiler-driven ideas were already isolated and native-tested.

## What counts as a quiche performance win

The downstream headline is **raw host-wide busy CPU seconds per steady inner-L3 Gbit**.

Do not promote a quiche optimization solely because:

- a quiche function gets faster in isolation,
- the `usque-rs` process uses less CPU,
- Cachegrind reports fewer instructions,
- or a saturated throughput point changes.

A quiche change can move cost into kernel networking. The full-host score deliberately includes userspace, kernel, IRQ/softirq, and fixed benchmark overhead.

Candidate-process CPU, kernel CPU, softirq counts, retransmits, and profiler counters are diagnostics.

## Keep the other layers pinned

When A/B testing a quiche change:

1. use the same usque commit;
2. use the same tun-rs commit;
3. use the same Rust compiler and lockfile;
4. keep usque runtime knobs identical;
5. change only the quiche artifact/commit;
6. record the final candidate binary hash.

The campaign found enough variation across compiler/dependency updates that a “latest stack vs old stack” comparison is not valid evidence for a quiche change.

## Useful screening points

For RX-path work on the high-tier EPYC host, 50 and 100 Mbit/s were useful screening/confirmation points:

- 50 Mbit/s retained enough headroom and often exposed fixed per-packet/per-poll costs clearly;
- 100 Mbit/s tested whether a win persisted at a more heavily loaded point;
- higher requested rates were often better interpreted as saturation/capacity tests rather than clean efficiency A/B points.

Always classify the point from achieved inner traffic and quality, not from the requested rate alone.

Promotion-grade samples used 8 seconds of steady traffic after warmup. Short smoke tests are functionality checks only.

## What we learned from the quiche hot-path work

A focused paired RX confirmation campaign found a real but rate-sensitive effect.

At high-tier RX 50 Mbit/s:

- median raw host CPU/Gbit delta: **-5.84%**,
- mean delta: -5.74%,
- 9 wins out of 12 pairs,
- median inner-throughput delta: -0.025%.

At RX 100 Mbit/s:

- median raw host CPU/Gbit delta: **-1.58%**,
- mean delta: +0.46%,
- 7 wins out of 12 pairs,
- median inner-throughput delta: +0.005%.

A later matched-final 100 Mbit/s comparison was essentially flat at about **-0.09%** host CPU/Gbit.

So the correct durable conclusion is not “the hot-path change is 6% faster”. It is:

> The change had a convincing effect at the 50-Mbit/s operating point in that environment, but the effect shrank and became inconsistent at 100 Mbit/s.

This is why quiche changes should be checked at more than one matched rate and, when practical, on more than one CPU class.

## Negative result worth remembering: receive-path outlining

One receive-path outlining experiment looked attractive if viewed only from the candidate process:

- candidate process CPU/Gbit: about **1.96% lower**,
- inner throughput: effectively unchanged.

Whole-host accounting rejected it:

- raw host CPU/Gbit: about **5.21% higher**,
- kernel accounting moved in the wrong direction.

Do not resurrect this idea from a userspace profile without explaining why the kernel-side regression would now be different.

## Closed quiche candidates

The canonical cross-repository ledger has the full history. These are the quiche-local dead ends most likely to look attractive again during a first-pass profile review.

### Batch timestamp reuse — rejected

Reusing one timestamp across a `recvmmsg` receive burst / UDP-GSO send burst looked plausible because clock acquisition was visible in profiles. The current-stack RX100 native campaign was unambiguous: five quality-clean pairs had idle-adjusted host CPU/Gbit deltas of `+3.93%, +4.36%, +8.50%, +1.53%, +12.87%`, median **+4.36%**, with **0/5 wins**. Do not revive the `*_at` API/timestamp branch without an architectural change that invalidates that result.

### Lost-frame / receive-path outlining — rejected

The current lost-frame outline campaign had five quality-clean RX100 pairs with a **+5.20% median host regression** and only 1/5 wins. An earlier receive-path outline also demonstrated the process-vs-host trap: process CPU/Gbit improved by about 1.96% while raw host CPU/Gbit regressed by about 5.21%.

Large `send_single`/receive functions and frontend counters are not, by themselves, a reason to retry outlining.

### Post-handshake idle fast paths — real work reduction, no whole-process win

Moving the established/no-post-handshake-data check before ExData construction and `TransportParams` cloning removed real work: roughly 5% fewer userspace instructions/user CPU in the relevant micro/paired measurements. The small-packet workload was about 80% system CPU, however, and same-path total process CPU stayed neutral/slightly worse. A cold/`inline(never)` slow-helper variant was also neutral and increased branch misses by about 8%.

Keep this as a useful userspace reference, not a performance change to re-propose by default.

The adjacent empty-0-RTT-queue fast path was only about 0.4% self in the profile and the later native review closed this family as too small to matter. Revisit only if a new profile makes it materially hotter.

### Cross-packet GSO send batching v1 — rejected

`send_gso_burst()` hoisted timestamp/path/handshake/PMTU work across an equal-segment burst. Stable pairs showed only ~0.79% median apparent process-CPU improvement while hardware counters got worse: about +4.6% instructions, +4.9% branches, and +4.7% branch misses. The apparent CPU win was not real executed-work reduction.

### DATAGRAM scatter-seal / Short packet fast path — rejected

- BoringSSL DATAGRAM scatter-seal / `extra_in`: wire-correct, about **2.6% worse CPU/bit**.
- DATAGRAM-only `write_pkt_type()` early Short fast path: about **+0.5% / noise**.

The separately tested direct DATAGRAM frame-accounting cleanup did survive its gate; do not conflate that accepted bookkeeping win with the rejected crypto/header shortcuts.

### Broader path/CID cache surgery — not justified

The SCID receive shortcut was a real small win and was retained. Broader active-path caching did not justify its extra state/invalidation complexity, and inline `ConnectionId` / short-header allocation removal was effectively noise (about -0.12% median across eight clean pairs). Start from the accepted SCID shortcut, not from broader cache surgery.

### `Vec<Acked>::drain(..)` rewrite — rationale invalid

An older hot-path stack rewrote `drain(..)` to slice iteration plus `clear()` under an allocation-churn rationale. Review established that `drain(..)` retains vector capacity and `Acked` has no drop glue; there was no independent benchmark supporting the churn. The rewrite was deliberately removed from the refreshed hot-path stack.

## Profiling workflow

The campaign used:

- Cachegrind / `cg_annotate`,
- native `perf`,
- hardware counters,
- L1/cache-focused counter passes,
- trace/perf comparisons,
- EPYC and Ryzen hosts where useful.

These tools were valuable for finding expensive receive-loop and packet-processing work, but their absolute results are not the production score.

Instrumentation changes scheduling and the kernel/userspace balance. Under Cachegrind, a 10-Mbit/s run could report tens of host CPU seconds/Gbit. That is useful for comparing annotated instruction paths inside the profiling experiment, not for comparing against native throughput runs.

Use this sequence:

1. find a real native bottleneck/regression;
2. reproduce a controlled workload under the profiler;
3. form one hypothesis;
4. make one focused change;
5. return to a native, pinned-stack, matched-rate A/B;
6. promote only if host CPU/Gbit improves and quality still passes.

## Measurement boundary

The downstream benchmark measures a complete CONNECT-IP forwarding path rather than only quiche.

Steady-state efficiency excludes establishment. Setup/handshake timing is recorded separately.

The useful-traffic denominator is TUN inner-L3 bytes rather than application goodput:

- RX uses TUN RX bytes,
- TX/UTX use TUN TX bytes.

That choice prevents QUIC/application timing differences from silently changing the denominator.

## Noise and repetitions

The calibrated standard window is 8 seconds. The same campaign showed that a 6-second prefix could still differ from the 8-second result by as much as 8.35%.

For effects of only a few percent, use paired repetitions and alternating candidate order. A single “green” run is not enough to distinguish a quiche win from host/network drift.

## Before merging a performance-oriented quiche change

At minimum:

- correctness tests pass;
- a smoke downstream tunnel run works;
- one or more non-saturated native A/B points pass quality;
- raw host CPU/Gbit agrees with the claimed direction;
- delivered inner traffic is equivalent;
- no meaningful loss/retransmit/softnet regression appears;
- the compiler and other two stack layers are pinned.

For a broad “faster” claim, confirm multiple rates and ideally both the high and low tiers. If the effect is architecture-specific or rate-specific, document it that way instead of averaging it into a universal percentage.
