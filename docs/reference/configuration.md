# 功能与配置入口

本页按当前实现组织公开能力，不表示这些功能都在 0.3.0 新增。版本变化见
[迁移指南](../guides/upgrading.md)和 CHANGELOG；精确签名、枚举值与错误类型以 rustdoc
和生成的 `lkrequest.h` 为准。

## 配置放在哪一层

| 层级 | 配置与状态 | 入口 |
|---|---|---|
| Client | 指纹、默认 headers、DNS、CA、timeouts、资源限制、缓存策略 | `Client::builder()` |
| Session | Cookie、连接池、代理、重定向、RetryPolicy、协议选择、网络分区上下文 | `client.session()` |
| Request | 单次 headers/body、代理覆盖、总超时、协议意图、幂等性、压缩、诊断 | `session.request()` / `get()` 等 |
| Operation | 一次发送的截止时间、HTTP 提交/建链计数、取消与结果 | `send()` / `send_streaming()` |

Client 是共享配置模板；Session 持有身份和网络状态。`AttemptLimits` 可在前三层配置，
在每次操作内独立计数，子级只能继承或收紧有限上限。其他配置各有覆盖规则：例如请求
`.timeout()` 只替换总超时，`.preset()` 在 Rust builder 中按调用顺序应用，而 C 的显式
profile override 优先于 preset。不要把一种配置的继承规则套到所有字段。

## 请求与身份

| 功能 | Rust 入口 | C ABI / 边界 | 指南 |
|---|---|---|---|
| 异步与同步请求 | `Client`、`blocking::Client` | `lk_request_send` / `lk_request_send_async` | [同步使用](../guides/blocking.md)、[FFI](../guides/ffi.md) |
| headers、顺序与 H1 大小写 | `header_typed`、`headers_ordered`、`http1_title_case_headers` | `lk_request_add_header`、`lk_request_add_header_order`、`lk_client_builder_set_http1_title_case_headers` | [请求配置](../guides/requests/) |
| JSON/form/multipart | `json`、`form`、`multipart` | `lk_request_set_json_text`、`lk_request_set_form`、`lk_request_set_multipart` | [请求体](../guides/requests/bodies.md) |
| 流式上传 | `body_reader`、`body_stream` | C 上传仍使用内存 body；一次性流不自动重放 | [流式上传](../guides/requests/streaming-upload.md) |
| 响应与流式下载 | `send_streaming`、`chunk`、`chunk_decoded` | `lk_request_send_streaming`、`lk_stream_read` / `lk_stream_read_async` | [响应处理](../guides/requests/responses.md) |
| 压缩协商 | `default_accept_encoding`、`accept_encoding`、`no_auto_decompress` | `lk_session_builder_set_default_accept_encoding`、`lk_request_set_accept_encoding`、`lk_request_set_auto_decompress` | [压缩与解压](../guides/requests/responses.md#压缩协商) |
| Cookie 读取、写入与清理 | `get_all_cookies`、`set_cookie_raw`、`set_cookie_with_attrs`、`clear_cookies` | `lk_session_get_all_cookies_json`、`lk_session_set_cookie_with_attrs`、`lk_session_clear_cookies`；C 无 raw Set-Cookie 写入入口 | [Cookie](../guides/requests/#cookie) |
| 重定向与显式重试 | `redirect_policy`、`retry_policy`、`idempotency` | `lk_session_builder_set_max_redirects`、`lk_session_builder_set_retry_fixed`；幂等性覆盖和自定义 RetryPolicy 为 Rust API | [请求配置](../guides/requests/)、[超时与重试](../guides/networking/timeouts.md) |
| 请求优先级 | `priority`、`h2_priority_weight` | `lk_request_set_h2_priority_weight`；C 无 `RequestPriority` setter | [请求优先级](../guides/requests/#请求优先级) |
| WebSocket | `Session::websocket`、blocking 同名入口 | 无 C ABI；仅 TLS + H1 Upgrade，压缩显式开启 | [WebSocket](../guides/websocket.md) |

## 网络、指纹与资源

| 功能 | Rust 入口 | C ABI / 边界 | 指南 |
|---|---|---|---|
| 内置浏览器 preset | `preset::chrome_157`、`firefox_156`、`safari_26` 等 | `lk_client_builder_set_preset`、preset discovery；默认 Chrome 155 | [选择 preset](../guides/choosing-a-preset.md) |
| 完整 Profile Bundle | `ClientPreset::from_json_*`、`PresetDocument`、`try_build` | `lk_client_builder_set_preset_json` / `set_preset_file`、`lk_preset_export_json` | [加载与导出](../guides/loading-profiles.md) |
| 独立 TLS/H2/QUIC profile | `fingerprint`、`h2_profile`、`quic_fingerprint`、`quic_profile` | 对应 `lk_client_builder_set_*_profile_json`；QUIC 需 `quic-h3` | [组件配置](../guides/loading-profiles.md#individual-profile-components) |
| 随机化 | `randomize` | `lk_client_builder_set_randomize`；synthetic 模式需 feature | [随机化](../guides/advanced/randomization.md) |
| 协议意图、发现与竞速 | `protocol_policy`、`http_intent`、`http1_only` / `http2_only` / `http3_only` | `lk_session_builder_set_http2_only` 等及 bundle runtime；C 不暴露全部 Rust 策略组合 | [协议策略](../guides/protocols.md)、[协议发现](../guides/advanced/protocol-discovery.md) |
| HTTP/SOCKS5/代理链、MASQUE | `proxy_config`、`ProxyConfig::parse_chain`、`masque` | `lk_proxy_config_*`、`lk_masque_config_*`；MASQUE 为可选实验功能 | [代理与 DNS](../guides/networking.md) |
| DNS、地址族与固定拨号 | `dns`、`dns_resolver`、`ip_family`、`connect_to` | DNS preset/地址/回调有 C API；`ip_family`、`connect_to` 当前为 Rust API | [网络路径](../guides/networking.md) |
| 证书、ECH、TAI | `use_native_certs`、`add_ca_*`、`verify`、`ech_config`、`trust_anchor_policy` | CA/ECH 与 TAI JSON 有 C API；`require_close_notify` 当前为 Rust API | [认证与证书](../guides/auth-and-certificates.md)、[TAI](../guides/networking/trust-anchor-identifiers.md) |
| 阶段、总计与读取空闲超时 | `TimeoutConfig`、`timeout` | `lk_client_builder_set_timeout_*` / `disable_timeout_*`、`lk_request_set_timeout` | [超时](../guides/networking/timeouts.md) |
| HTTP 重发与建链上限 | `attempt_limits`、`effective_attempt_limits` | `lk_*_set_*_attempt_limit` / getter / clearer | [次数与继承](../guides/client-session.md#请求重发上限与统计) |
| TLS/QUIC 恢复、缓存与分区 | `tls_session_resumption_policy`、`tls_session_cache_*`、`network_partition_context` | 缓存启停/TTL、`lk_client_builder_set_session_resumption_json`；完整分区策略组合为 Rust API | [缓存](../guides/client-session.md#tlsquic-会话缓存)、[分区](../guides/limits.md#会话票据分区) |
| 响应大小、速率与连接容量 | `ResourceLimits`、`max_connections` | `lk_client_builder_set_max_response_body_size` / `set_min_transfer_rate` 等、`lk_session_builder_set_max_connections` | [资源限制](../guides/limits.md) |
| H2 排队、批处理与 DATA 分帧 | `max_pending_h2_requests`、`h2_dispatch_batch_size`、`h2_data_frame_policy` | 当前为 Rust API；改变批处理/分帧可能改变指纹 | [高并发](../guides/advanced/high-throughput.md#h2-排队与写入配置) |
| Pool、预热与预取 | `SessionPool`、`ProxyPool`、`preconnect`、`prefetch` | Pool 与 preconnect 有 C API；prefetch 为 Rust API | [Pool](../guides/advanced/high-throughput.md)、[预热](../guides/advanced/protocol-discovery.md) |
| 请求诊断、摘要与日志 | `collect_diagnostics`、`observe_attempts`、`Middleware`、`keylog` | diagnostics/summary/logging/telemetry 有 C API，key log 用 `lk_client_builder_set_keylog_file`；Rust Middleware 与 keylog callback 无对应 C 入口 | [可观测性](../guides/advanced/observability.md)、[Middleware](../guides/advanced/middleware.md) |

独立使用底层协议的开发者，另见 [crate 选型](../development/crates.md)。
`CompiledClientConfig`、TLS connection state machine 和协议 engine 的接口不要求普通
HTTP 应用直接管理。Cargo features 和运行环境限制见[功能能力](capabilities.md)。
