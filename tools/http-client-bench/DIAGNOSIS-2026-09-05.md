# HTTP/2 performance-gap diagnosis — 2026-09-05

This investigation explains the original large difference between lkrequest,
Hyper, and reqwest in the local h2c benchmark. Fingerprint fidelity, TLS, and
connection setup are outside this workload: every measured client reuses one
HTTP/2 connection and fully consumes each response body.

## Root cause of the latency cliff

The comparison was not using equivalent TCP behavior:

- Hyper and reqwest explicitly enabled `TCP_NODELAY` in the benchmark.
- The direct `lkh2` diagnostic client also enabled `TCP_NODELAY`.
- A default lkrequest client had no TCP fingerprint, so it left Nagle's
  algorithm enabled.

With many small HTTP/2 frames, Nagle interacting with delayed ACKs produced the
original 10–25 ms p99 latency cliff. An A/B run that changed only
`TCP_NODELAY` raised lkrequest concurrency-32 throughput from roughly
19–24k req/s to 30–34k req/s and reduced p99 from roughly 16–17 ms to
2.7–4.2 ms.

The transport now enables `TCP_NODELAY` before applying an optional TCP
fingerprint. A fingerprint that explicitly specifies `tcp_nodelay = false`
still overrides the transport default, preserving deliberate wire behavior.

## Corrected comparison

The corrected matrix used three alternating-order rounds, one client runtime
worker, two server runtime workers, one reused h2c connection, and zero failed
requests.

| Scenario | Client | Throughput | p99 |
|---|---|---:|---:|
| Sequential reuse, 1 KiB | lkrequest | 18,715 req/s | 117 us |
| Sequential reuse, 1 KiB | Hyper | 27,891 req/s | 85 us |
| Sequential reuse, 1 KiB | reqwest | 24,440 req/s | 96 us |
| Concurrency 8, 1 KiB | lkrequest | 31,715 req/s | 431 us |
| Concurrency 8, 1 KiB | Hyper | 54,865 req/s | 327 us |
| Concurrency 8, 1 KiB | reqwest | 66,945 req/s | 258 us |
| Concurrency 32, 1 KiB | lkrequest | 34,449 req/s | 1,357 us |
| Concurrency 32, 1 KiB | Hyper | 167,007 req/s | 492 us |
| Concurrency 32, 1 KiB | reqwest | 108,726 req/s | 702 us |
| Concurrency 128, 1 KiB | lkrequest | 34,577 req/s | 4,735 us |
| Concurrency 128, 1 KiB | Hyper | 156,179 req/s | 1,355 us |
| Concurrency 128, 1 KiB | reqwest | 120,200 req/s | 1,442 us |
| Concurrency 32, 1 MiB | lkrequest | 844 MiB/s | 80,989 us |
| Concurrency 32, 1 MiB | Hyper | 810 MiB/s | 84,829 us |
| Concurrency 32, 1 MiB | reqwest | 833 MiB/s | 115,144 us |

The fix removes the abnormal millisecond-scale cliff. Large-body throughput is
already comparable. A real small-request concurrency gap remains.

## Remaining bottleneck

Loopback packet capture for 20,000 requests at concurrency 32 showed:

| Client | Client-to-server TCP payload packets | Average payload | Packets/request |
|---|---:|---:|---:|
| lkrequest | 20,132 | 21.1 bytes | 1.007 |
| direct lkh2 | 19,849 | 20.4 bytes | 0.992 |
| Hyper | 2,149 | 141.1 bytes | 0.107 |
| reqwest | 1,570 | 193.2 bytes | 0.078 |

The lkrequest/lkh2 path therefore emits approximately one tiny TCP payload per
request, while Hyper and reqwest coalesce roughly 9–13 requests' frames into
each payload. The lkh2 driver receives and dispatches commands individually,
creates a fresh output buffer for each frame group, then calls `write_all` and
`flush`. The benchmark is now primarily measuring that dispatch and syscall
pattern rather than an unexplained network delay.

The next performance change should drain multiple ready request commands and
coalesce their encoded frames into a bounded write buffer. Because batching can
change TCP/TLS record boundaries and browser-fingerprint behavior, it should be
an explicit performance mode or a separately validated profile option rather
than an unconditional change to fingerprint-sensitive operation.

That opt-in mode and its single-session, multi-session, and packet-capture A/B
results are documented in `AB-BATCHING-2026-09-05.md`.

## Tooling notes

- Low-level diagnostic clients isolated the slowdown below redirect, retry, and
  middleware processing.
- A/B TCP socket configuration identified the main latency cause.
- Wireshark `dumpcap`/`tshark` quantified write coalescing without relying on
  timing inference alone.
- Windows ETW/WPR profiling was prepared with release debug symbols, but kernel
  tracing was denied by the current non-administrator session. It remains useful
  for the next driver optimization, especially for syscall and scheduler costs.
