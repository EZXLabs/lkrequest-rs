# HTTP/2 dispatch batching A/B — 2026-09-05

This experiment tests an explicit throughput mode while keeping the default
fingerprint-sensitive scheduling unchanged.

## Implementation

The default driver configuration still dispatches one ready request per write.
The opt-in mode:

- yields only when the connection already has an in-flight stream;
- drains up to 64 currently ready request commands;
- preserves request and frame order;
- encodes up to 64 requests into one socket write;
- caps each accumulated write at 64 KiB;
- does not change SETTINGS, HPACK, pseudo-header order, or frame bytes.

The high-level switch is:

```rust
let client = Client::builder()
    .h2_dispatch_batch_size(64)
    .build();
```

Values above one can change TLS record boundaries, TCP segmentation, and
timing. The default remains one and should be retained for fingerprint-sensitive
profiles unless a real-browser capture validates the alternative behavior.

## Single-session A/B

Windows loopback h2c, 1 KiB responses, one client runtime worker, two server
runtime workers, reused connection, alternating client order, zero failures.

| Concurrency | Mode | Median req/s | Median p99 | Change |
|---:|---|---:|---:|---:|
| 1 | default | 18,980 | 110 us | baseline |
| 1 | batch64 | 19,125 | 104 us | +0.8% |
| 32 | default | 33,418 | 1,401 us | baseline |
| 32 | batch64 | 46,973 | 977 us | +40.6% |

The in-flight condition avoids the low-concurrency regression observed with an
earlier unconditional-yield prototype.

## Multi-session A/B

Total concurrency remained 32 while independent Session count changed. Each
row is the median of three alternating-order rounds.

| Sessions | Concurrency/session | Default req/s | Batch64 req/s | Throughput change | Default p99 | Batch64 p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 32 | 33,997 | 46,891 | +37.9% | 1,395 us | 987 us |
| 4 | 8 | 35,104 | 41,132 | +17.2% | 1,674 us | 1,302 us |
| 8 | 4 | 34,681 | 37,499 | +8.1% | 1,764 us | 1,621 us |
| 32 | 1 | 30,280 | 30,511 | +0.8% | 2,827 us | 2,803 us |

The optimization acts per connection. Its benefit therefore decreases as total
concurrency is divided across more independent sessions and H2 connections.

## Packet capture

For 20,000 requests at concurrency 32 over one H2 connection:

| Mode | Client-to-server payload packets | Average payload | Packets/request |
|---|---:|---:|---:|
| default | 20,954 | 21.1 bytes | 1.05 |
| batch64 | 2,610 | 169.0 bytes | 0.13 |

Both captures carried the same 441,147 TCP payload bytes. Batch64 reduced
client-to-server payload packet count by 87.5%, confirming that the throughput
gain comes from fewer small writes rather than skipped work.

## Conclusion

Batching is valuable for high multiplexing on one H2 connection and remains
useful for a small number of busy sessions. It provides almost no benefit when
every session has only one in-flight request. It must remain opt-in until its
TLS-record and packet-timing behavior is compared with real Chrome captures.
