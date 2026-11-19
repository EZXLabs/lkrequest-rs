# Timeouts and Explicit Retries

The default total request timeout is 120 seconds. It covers connection setup,
upload, redirects, explicitly configured retries, retry backoff, and response
body reads. All of these share one deadline created when `send()` or
`send_streaming()` begins. Streaming body reads retain it after headers return.

Phase limits remain active. For example, DNS and response-header limits of
30 seconds with a total of 10 seconds allow at most 10 seconds for the whole
operation. The timer that expires first terminates the operation.

## Defaults and Configuration

| `TimeoutConfig` field | Default | Rust setter / scope |
| --- | --- | --- |
| `dns_timeout` | 5 s | `.dns_timeout(...)`, name resolution |
| `tcp_connect_timeout` | 10 s | `.tcp_connect_timeout(...)`, TCP connection |
| `tls_handshake_timeout` | 10 s | `.tls_handshake_timeout(...)`, TLS handshake |
| `quic_connect_timeout` | 10 s | `.timeout_config(...)`, QUIC connection |
| `ttfb_timeout` | 30 s | `.ttfb_timeout(...)`, upload and complete response headers |
| `read_idle_timeout` | Disabled | `.read_idle_timeout(...)`, each pending body read |
| `total_timeout` | 120 s | `.total_timeout(...)`, whole HTTP operation |

Build a `TimeoutConfig` with `Default` or `none()` and the `with_*` helpers, or
assign its public fields. `.timeout_config(config)` replaces the complete
configuration; later individual setters replace just their field. Inspect the
effective client settings with `client.timeouts()`.

The legacy `.connect_timeout(duration)` splits its value between TCP and TLS;
unused time does not transfer between phases. `.read_timeout(duration)` is an
alias for the total timeout, not the read-idle limit. Their legacy getters use
`Duration::MAX` for a disabled deadline; prefer `client.timeouts()` to distinguish
the individual `Option<Duration>` values. Rust zero durations and C zero
milliseconds mean an immediate timeout.

The `ttfb_timeout` name is retained for compatibility. Its actual scope includes
request upload and waiting for complete response headers, rather than only the
first response byte. Response body reads use the total and optional idle limits.

```rust,no_run
use lkrequest::{Client, FixedInterval, TimeoutConfig};
use std::time::Duration;

let client = Client::builder()
    .total_timeout(Duration::from_secs(120))
    .read_idle_timeout(Duration::from_secs(15))
    .build();

// Session retries are disabled until a caller installs a policy.
let session = client.session()
    .retry_policy(FixedInterval::new(2, Duration::from_millis(250)))
    .build();
```

`read_idle_timeout` is disabled by default. When configured, it limits how long
a pending response body read can wait without data. It applies to buffered and
streaming responses. Cancellation and resumption of a pending streaming chunk
do not reset its idle budget. Time spent processing a completed chunk does not
consume the next read's idle budget, but still consumes the total deadline.

For SSE and other long-lived streams, disable the total deadline independently:

```rust,no_run
use lkrequest::{Client, TimeoutConfig};
use std::time::Duration;

let timeouts = TimeoutConfig {
    total_timeout: None,
    read_idle_timeout: Some(Duration::from_secs(45)),
    ..TimeoutConfig::default()
};
let client = Client::builder().timeout_config(timeouts).build();
```

The request's `.timeout(duration)` overrides the client's total timeout only.
Other configured connection and response-header phase limits remain active.
Every `TimeoutConfig` field uses `None` to disable its corresponding client
deadline. `TimeoutConfig::none()` disables all of them; no finite default is
substituted. To remove every client request deadline:

```rust,no_run
use lkrequest::{Client, TimeoutConfig};

let client = Client::builder().timeout_config(TimeoutConfig::none()).build();
```

Operating-system errors and independently configured resolver or transport
protocol limits still apply. For example, QUIC transport idle parameters are
part of the selected wire profile and are separate from request deadlines.

## Retry Configuration

Session retries, closed-connection request replay, and H2-to-H1 fallback are
disabled by default. A safe method or an idempotency declaration makes a request
eligible for replay only after a caller authorizes retries. It does not enable
retries on its own.

- `.session().retry_policy(...)` authorizes policy-controlled retries.
- `.retry_on_connection_close(true)` authorizes bounded connection recovery.
- `.h2_fallback_h1(true)` authorizes H2-to-H1 fallback.
- `.h3_retry_mode(...)` selects the explicit HTTP/3 protocol-error retry mode.

Configured protocol selection and connection establishment can choose an
available transport before an HTTP request is sent. TCP/QUIC packet retransmission
remains part of their transport protocols. These are separate from repeating an
HTTP request after a failure.

HTTP/3 0-RTT is independent of the connection-close retry flag. A resumable
session and a replay-safe method or explicit idempotency declaration permit
early data. Rejected early data can be sent again after handshake confirmation;
the server must not process rejected early data. Accepted early-data failures
still follow the configured retry policy and attempt budget.

Timeouts are cooperative: synchronous middleware, synchronous decompression,
and a blocking upload reader already executing cannot be forcibly interrupted.

## Attempt Limits

`AttemptLimits` adds optional ceilings for extra HTTP submissions and actual
TCP/QUIC connection starts. Both are unset by default. Limits configured on a
Client or Session apply independently to each operation; they are not shared
quotas across concurrent requests. Child settings inherit or tighten a finite
parent limit and cannot enable recovery forbidden by another policy.

Initial submissions and permitted redirects do not use extra-HTTP allowance.
Pooled reuse and waiting for another request's connection consume no new
connection start. Failed starts and race losers remain counted. Transport packet
retransmissions do not create another HTTP submission.

An attempt limit does not install a deadline. Waiting for a shared connection,
retry backoff and subsequent attempts retain the original total deadline.
Streaming attempt summaries become final when response headers are returned,
while the same total deadline still applies to reading the body.

See [configuration and accounting](../client-session.md#请求重发上限与统计) and
[attempt summaries](../advanced/observability.md#请求尝试摘要) for examples.

## C ABI

`lk_client_builder_set_timeout_total(builder, milliseconds)` enables the total
deadline. `lk_client_builder_disable_timeout_total(builder)` disables it.
`lk_client_builder_set_timeout_read_idle(builder, milliseconds)` enables the
body read-idle timer; `lk_client_builder_disable_timeout_read_idle(builder)`
disables it. Zero milliseconds is an immediate timeout, not a disable sentinel.
Feature discovery names are `optional-total-timeout` and `read-idle-timeout`.
The phase disable functions are `lk_client_builder_disable_timeout_dns`,
`lk_client_builder_disable_timeout_tcp_connect`,
`lk_client_builder_disable_timeout_tls_handshake`,
`lk_client_builder_disable_timeout_quic_connect`, and
`lk_client_builder_disable_timeout_ttfb`. Each phase's existing setter enables
its deadline again. Feature discovery name: `optional-phase-timeouts`.

Retry controls are `lk_session_builder_set_retry_fixed`,
`lk_session_builder_set_retry_exponential`,
`lk_client_builder_set_retry_on_connection_close`, and
`lk_client_builder_set_fallback_h2_to_h1`.
