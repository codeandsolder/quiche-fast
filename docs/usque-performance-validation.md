# Downstream performance validation with usque

`quiche-fast` is performance-sensitive in ways that are difficult to capture with a library-only microbenchmark. A change can reduce instructions inside quiche while changing syscall frequency, packet pacing, wakeups, buffering, or kernel work.

For that reason, the September–October 2026 optimization campaign used the full `usque-rs-fast -> quiche-fast -> tun-rs-fast` stack as a downstream validation harness.

The canonical methodology and campaign history live in:

- https://github.com/codeandsolder/usque-rs-fast/blob/main/docs/BENCHMARKING.md

This page records the quiche-specific lessons so they are visible to someone working in this repository.

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
