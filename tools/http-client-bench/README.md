# HTTP/2 client performance benchmark

This tool compares `lkrequest`, Hyper, and reqwest using the same HTTP/2
prior-knowledge workload. It intentionally excludes browser fingerprint and
protocol-conformance testing.

## Scope

- Cleartext HTTP/2 (`h2c`) isolates HTTP/2 client, pooling, body delivery, and
  runtime overhead from TLS implementation differences.
- The server runs in a separate process.
- Accepted server sockets use `TCP_NODELAY`, matching every benchmark client
  and avoiding server-side Nagle/delayed-ACK artifacts.
- Each client is created once, warmed up, and reused for the measured workload.
- The runner creates a fixed number of workers rather than one task per request.
- Every response body is fully consumed and its size is validated.
- The server returns `x-bench-connection-id`, allowing reports to show how many
  H2 connections were actually observed.

The initial suite does not measure fresh TCP/TLS/H2 setup. That requires a
separate TLS fixture with identical trust and crypto settings for every client.

## Build

```bash
cargo build --release -p http-client-bench
```

## Run one benchmark

Start the server in one terminal:

```bash
target/release/http-client-bench serve \
  --listen 127.0.0.1:18481 \
  --body-size 1024 \
  --runtime-workers 2
```

Run a client in another terminal:

```bash
target/release/http-client-bench run \
  --client lkrequest \
  --url http://127.0.0.1:18481/ \
  --requests 50000 \
  --concurrency 32 \
  --sessions 1 \
  --warmup-requests 200 \
  --expected-bytes 1024 \
  --runtime-workers 1 \
  --output benchmark-results/lkrequest-c32.json
```

Repeat with `--client hyper` and `--client reqwest`.

`--sessions` creates independent clients/sessions and distributes workers
across them. Warm-up requests are applied to every session so every measured
session has an established H2 connection before timing begins.

Two diagnostic clients are also available for bottleneck isolation:

- `lkh2` exercises the low-level HTTP/2 engine directly.
- `lkh2-drain64` drains ready commands but preserves one request per write.
- `lkh2-batch64` additionally batches up to 64 requests per write.
- `lkrequest-transport` bypasses redirect, retry, and middleware processing but
  keeps lkrequest's transport and connection-pool path.
- `lkrequest-batch64` exercises the public
  `ClientBuilder::h2_dispatch_batch_size(64)` throughput mode.

They are intentionally excluded from the standard comparison matrix because
they are implementation probes rather than public high-level clients.

The default dispatch batch size is one. Values above one can change TLS record
boundaries, TCP segmentation, and timing behavior, so browser-fingerprint
profiles must keep the default unless the resulting capture is independently
validated.

## Standard matrix

PowerShell:

```powershell
./tools/http-client-bench/scripts/run-matrix.ps1
```

Bash:

```bash
./tools/http-client-bench/scripts/run-matrix.sh
```

The scripts run three alternating-order rounds by default:

| Scenario | Body | Requests | Concurrency |
|---|---:|---:|---:|
| `sequential-reuse` | 1 KiB | 20,000 | 1 |
| `multiplex-c8` | 1 KiB | 30,000 | 8 |
| `multiplex-c32` | 1 KiB | 50,000 | 32 |
| `multiplex-c128` | 1 KiB | 50,000 | 128 |
| `download-1m-c32` | 1 MiB | 1,000 | 32 |

Set `ROUNDS` for Bash or `-Rounds` for PowerShell to change the number of rounds.
The scripts also write `environment.txt`, `summary.json`, and `SUMMARY.md`.

Use `-ClientRuntimeWorkers 4 -ServerRuntimeWorkers 4` in PowerShell, or set
`CLIENT_RUNTIME_WORKERS=4 SERVER_RUNTIME_WORKERS=4` in Bash, to measure
multi-thread runtime scaling separately from the default single-worker client.

## Report fields

Each JSON report contains:

- Successful and failed requests.
- Requests per second and MiB per second.
- Minimum, mean, p50, p90, p95, p99, and maximum latency.
- Observed H2 connection IDs and count.
- User/system CPU time consumed during the measured interval.
- Process peak resident set size.
- Workload, runtime-worker, OS, and architecture metadata.
- Exact client-library, Tokio, and benchmark-tool versions captured at build time.

Peak RSS is the process lifetime high-water mark. Run each workload in a new
client process, as the matrix scripts do, to keep that metric meaningful.

## Measurement guidance

- Use a dedicated Linux host for publishable results.
- Keep CPU governor, runtime worker count, compiler, and dependency versions fixed.
- Run clients in alternating order and retain every raw JSON report.
- Compare median rounds and report round-to-round variation.
- Keep TCP behavior matched. The benchmark clients use `TCP_NODELAY`; lkrequest
  now also enables it by default unless a TCP fingerprint explicitly requests
  `tcp_nodelay = false`.
- Do not use shared GitHub-hosted runner numbers as release performance claims.
- Keep the benchmark server below saturation; validate it separately with
  `h2load` when testing high request rates.

See `DIAGNOSIS-2026-09-05.md` for the investigation of the original large
concurrency gap, the corrected matrix, and packet-capture evidence for the
remaining HTTP/2 dispatch bottleneck.

See `AB-BATCHING-2026-09-05.md` for the write-batching implementation and its
single-session, multi-session, and packet-capture A/B results.

See `LINUX-RESULTS-2026-09-05.md` for the five-round Ubuntu/KVM comparison,
multi-session scaling, `strace` evidence, environment limitations, and raw
result archive hash.

See `FLAMEGRAPH-DEFAULT-2026-09-05.md` for the default single-session c32 CPU
profile and the HPACK Huffman decoder construction bottleneck.

See `FLAMEGRAPH-HPACK-SELF-2026-09-05.md` for the matched re-profile after
removing `fluke-hpack`, including the eliminated Huffman construction hotspot
and the new socket-write bottleneck.

See `AB-NATIVE-HEADERS-2026-09-05.md` for the seven-round Linux A/B of the
direct native request path and single-pass response header parsing.

The complete performance-fix summary and Linux validation plan are documented in
[`docs/http2-performance.md`](../../docs/http2-performance.md). Write-level
fingerprint considerations are covered separately in
[`docs/h2-write-batching.md`](../../docs/h2-write-batching.md).
