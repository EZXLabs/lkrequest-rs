# HTTP client performance benchmark

The default workload compares `lkrequest`, Hyper, and reqwest using HTTP/2
prior knowledge. Additional lkrequest-only fixtures cover HTTP/1, HTTP/3,
and TLS-H2/QUIC-H3 acquisition races. This is a performance harness, not a
browser fingerprint or protocol-conformance test.

## Scope

- Cleartext HTTP/2 (`h2c`) isolates HTTP/2 client, pooling, body delivery, and
  runtime overhead from TLS implementation differences.
- The server runs in a separate process.
- Accepted server sockets use `TCP_NODELAY`, matching every benchmark client
  and avoiding server-side Nagle/delayed-ACK artifacts.
- By default each client/session is created once, warmed up, and reused.
- Cold workloads retain the client and construct a new Session for each request.
- The runner creates a fixed number of workers rather than one task per request.
- Every response body is fully consumed and its size is validated.
- The server returns `x-bench-connection-id`, allowing reports to show how many
  physical connections delivered responses. TCP and QUIC share one ID namespace.
- Negotiated protocol, status, body size, and connection ID are validated.

## Build

```bash
cargo build --release -p http-client-bench
```

Add `--features quic-h3` for the local HTTP/3 and race fixtures. Use the same
harness sources, feature flags, compiler, and dependencies in baseline and
candidate binaries.

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

Use `--client lkrequest-streaming` to measure the public `send_streaming()` path.
It drains `chunk()` to EOF, counting and immediately dropping each chunk without
collecting a buffered body. Status, total body bytes, connection ID, and protocol
use the same report fields and validation as the buffered client. This mode
supports all lkrequest protocols and both lifecycle settings below.

`StreamingResponse` does not expose a protocol-version getter, so streaming
samples require the fixture's `x-bench-protocol` header (`h1`, `h2`, or `h3`).
The fixture records the protocol actually handling the request, including the
winning race transport. Missing or unknown protocol markers fail the request;
the client does not infer a race winner from its configuration. Use the updated
fixture and identical harness sources for both baseline and candidate binaries.

`--sessions` creates independent client groups and distributes workers across
them. In the default `--lifecycle warm` mode each group retains one Session;
warm-up requests are applied to every group before timing begins. In
`--lifecycle cold` mode every request creates and drops a Session from its
group's retained Client. Client construction is excluded; Session creation,
connection setup, request, full body consumption, and Session drop are included.

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

## Additional lkrequest workloads

For cleartext HTTP/1, start `serve --protocol h1 --listen 127.0.0.1:18481` and
run with `--protocol h1`. Use `--lifecycle cold --warmup-requests 0` to measure
new Sessions and connections. `h2c` supports the same lifecycle selection.
Non-lkrequest clients reject modes other than `h2c` and `warm`.

Build the QUIC-enabled binary, then run an HTTP/3 fixture:

```bash
cargo build --release -p http-client-bench --features quic-h3
target/release/http-client-bench serve --protocol h3 \
  --listen 127.0.0.1:18483 --stats-output benchmark-results/h3-server.json
```

In another terminal:

```bash
target/release/http-client-bench run --client lkrequest --protocol h3 \
  --url https://localhost:18483/ --lifecycle cold --warmup-requests 0 \
  --requests 1000 --concurrency 8 \
  --server-stats benchmark-results/h3-server.json \
  --output benchmark-results/h3-cold.json
```

For a real acquisition race, the fixture listens on TCP and UDP at the same
address and port. TCP serves TLS-H2 and UDP serves QUIC-H3:

```bash
target/release/http-client-bench serve --protocol race \
  --listen 127.0.0.1:18484 --stats-output benchmark-results/race-server.json
```

In another terminal:

```bash
target/release/http-client-bench run --client lkrequest --protocol race \
  --url https://localhost:18484/ --lifecycle cold --warmup-requests 0 \
  --requests 1000 --concurrency 8 \
  --server-stats benchmark-results/race-server.json \
  --output benchmark-results/race-cold.json
```

TLS fixtures use a generated localhost certificate and disabled client
certificate verification, and are restricted to loopback. The client uses a
Chrome 155 preset, disables TLS session resumption, and supplies an explicit
resolver mapping the URL to the fixture address and port with an HTTPS RR
advertising `h3` and `h2`. Race policy enables both jobs with zero delay and
disables sequential fallback and detached probes. The winner may be H2 or H3.
These controlled settings do not reproduce browser or internet timing.

Race mode requires `--server-stats`. The runner accepts only fresh, complete
snapshots for the configured address/protocol, retries reads for up to two
seconds, and rejects server restarts or counter regressions. Reports separate
warm-up and measured deltas. Cold race qualification requires both TCP accepts
and QUIC Initial arrivals in the measured delta; warm race qualification can
use either window because measured requests may reuse a pooled winner.
Missing evidence fails the run even when every HTTP response succeeded.
Counts prove both transports started during the selected window, not that
every request started both or that both handshakes completed. `observed_protocols`
records only successful response protocols. Race cancellation can increase
`connection_failures` on the losing transport.

Use a dedicated server instance and stats file for one benchmark at a time.
Counters cannot attribute concurrent unrelated traffic. Stats snapshots are
sampled every 100 ms; final measured deltas can include connection cleanup
between the last response and the next snapshot. Response connection IDs count
only connections delivering successful responses, while server counters also
include losing/failed connections. Start cold experiments with zero warm-up.

## Allocation samples

Throughput runs default to `--allocations false`. Run separate allocation
samples using the same configuration with `--allocations true`; do not compare
their throughput against uninstrumented samples. The System allocator wrapper
counts allocation/zeroed-allocation calls, reallocations, and requested bytes.
Reallocation bytes are the full requested new size, not the growth amount.
These are process-wide cumulative counts, not live or peak allocated memory.

Counters reset after warm-up and all workers reach the ready barrier, then
stop after workers finish. Client setup, initial worker buffers, server-stat
reads, CPU sampling, result aggregation, percentile calculation, and report
JSON are outside this window. Runtime work, request bookkeeping, buffer growth,
and background connection cleanup during the window remain included. Clock
reads do not allocate. Allocations already entering the wrapper at a boundary
can straddle the window, so use multiple runs and sufficiently large samples.
The disabled wrapper still performs one boolean load per allocation/reallocation;
baseline and candidate must contain identical instrumentation code.

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
- Observed physical connection IDs/count and successful response protocols.
- Protocol/lifecycle, optional allocation counts, and optional server evidence.
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
