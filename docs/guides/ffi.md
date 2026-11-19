# C ABI 与其他语言绑定

`lkrequest-ffi` 将 Client、Session、Request、Response、StreamingResponse、ProxyPool、SessionPool 和 Multipart 暴露为稳定 opaque handles。完整符号和所有权规则见 crate 根目录的 `lkrequest-ffi/README.md`。

0.3.0 的 C ABI 版本仍为 `1`。使用 `lk_library_version()` 读取库版本，使用 `lk_abi_version()` 检查 ABI；新增能力通过 `lk_feature_supported()` 查询。Rust 调用方应使用 `lkrequest` 的正式 API，FFI crate 导出的内部 Handle/State Rust 结构不属于稳定字面量兼容范围。

## 构建动态库

```bash
cargo build -p lkrequest-ffi --release
```

需要 H3/QUIC ABI 时：

```bash
cargo build -p lkrequest-ffi --release --features quic-h3
```

平台动态库名称由 Cargo target 决定，例如 Windows DLL、Linux `.so` 或 macOS `.dylib`。绑定应从发布包或实际 target 目录解析产物，不要硬编码开发机绝对路径。

H2 始终由 `lkh2` 提供，不需要 Cargo feature；关闭默认 feature 也保留 H2。旧 Cargo 配置的调整见[0.3.0 迁移说明](upgrading.md)。

## 生成 header

`lkrequest-ffi/include/lkrequest.h` 是未跟踪构建产物。CI、发布任务或绑定构建必须自行生成：

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

正常 `cargo build` 在找到 `cbindgen` 时也会由 `build.rs` 生成 header；未安装时 Rust crate 仍可构建，但不会产生 header。

## 所有权规则

- 每个 opaque handle 必须使用对应的 `*_free` 释放。
- Client、Session 和 Op 可以共享；Request 与 StreamingResponse 是单 owner。
- borrowed pointer 由产生它的 handle 所有，不能由调用方释放。
- streaming chunk pointer 会在下一次修改性读取、close 或 free 后失效。
- async API 返回 Op；绑定必须等待完成并使用匹配的 `take_*` 取得结果。
- 错误 handle 也必须按 API 约定读取和释放，不能只记录裸指针。

## 次数上限与请求诊断

这些 API 无需额外 Cargo feature。绑定应在加载库后检查能力：

| 能力名称 | 用途 | 主要入口 |
|---|---|---|
| `extra-http-attempt-limit` | 单次请求的额外 HTTP 提交上限 | `lk_*_set_extra_http_attempt_limit`、`lk_*_clear_extra_http_attempt_limit` |
| `connect-attempt-limit` | 单次操作的 TCP/QUIC 建链上限 | `lk_*_set_connect_attempt_limit`、`lk_*_clear_connect_attempt_limit` |
| `attempt-summary` | 请求计数与拒绝原因 | `lk_request_enable_attempt_summary`、`lk_*_copy_attempt_summary_json` |
| `tls-session-cache` | 缓存启停和 TTL | `lk_client_builder_set_tls_session_cache_enabled`、`lk_client_builder_set_tls_session_cache_ttl`、`lk_client_builder_reset_tls_session_cache_ttl` |

次数 setter/clearer 适用于 Client builder、Session builder 和 Request；对应 getter 也支持已构建的 Client、Session，以 `lk_attempt_limit_view_t` 区分本层配置、有效值和来源。两个上限默认不启用；子级只能继承或收紧有限上限，零是有效上限，clear 表示恢复继承。限制和计数都是每次操作独立的，不会因为共享 Session 而共享额度。详见[计数语义](client-session.md#请求重发上限与统计)。

发送前使用 `lk_request_enable_attempt_summary` 开启摘要收集，它与原 diagnostics JSON 独立。完成后使用 `lk_response_copy_attempt_summary_json`、`lk_streaming_response_copy_attempt_summary_json` 或 `lk_error_copy_attempt_summary_json`；异步操作可使用 `lk_op_copy_attempt_summary_json`，结果被取走或取消后仍可读取，直到 `lk_op_free`。

复制 JSON 时先传 `NULL` buffer 和零容量查询长度，再提供调用方缓冲区。返回内容不含末尾 NUL；容量不足时缓冲区不变，并返回所需长度。活动快照可能增长，需要按新长度重试。取消是异步的，JSON 中的 `final` 为真才表示请求执行已结束；流式摘要在 headers 返回时固定，后续 body 错误另行处理。

缓存 TTL 的单位是毫秒，零表示不缓存；reset 恢复版本对应的默认期限，不改变缓存启停状态。缓存开关不会关闭已有连接池连接。

连接关闭重发与 H2-to-H1 回退默认关闭。需要时分别使用 `lk_client_builder_set_retry_on_connection_close` 和 `lk_client_builder_set_fallback_h2_to_h1`，并保留方法幂等性、body 重放和协议限制。所有 timeout setter 的单位与关闭方式见[超时与显式重试](networking/timeouts.md#c-abi)。

## 其他能力查询

`lk_feature_supported` 接收 NUL 结尾的能力名称。下表与上面的四个名称一起构成当前查询面；
未知名称返回 `false`。能力名称不是 Cargo feature 的通用映射，不能直接拿任意 Cargo
feature 名称查询。

| 能力名称 | 可用条件与入口 |
|---|---|
| `sync`、`async`、`streaming` | 始终支持；Request send、Op、Stream read |
| `preset-discovery` | 始终支持；preset 列表与 detail JSON |
| `preset-bundle-v2` | 始终支持；完整配置加载、导出及错误路径，见[Profile Bundle](loading-profiles.md) |
| `tls-profile-json`、`h2-profile-json` | 始终支持；独立组件覆盖，见[组件输入](loading-profiles.md#individual-profile-components) |
| `quic-profile-json`、`quic-tls-profile-json` | 需要 `quic-h3` |
| `http3`、`quic-h3`、`http3-with-fallback` | 同为 `quic-h3` 的可用性查询 |
| `diagnostics` | 始终支持；请求诊断，与 attempt summary 独立 |
| `logging`、`logging-callback` | 始终支持；文件或回调日志 |
| `multipart`、`proxy-pool`、`session-pool` | 始终支持；相应 handle API |
| `dns`、`dns-custom-resolver` | 始终支持；内置选择与宿主 resolver 回调，具体 DoH 选项仍需 `doh` |
| `socks5-udp-probe` | 始终支持；代理 UDP 探测，不表示已编译 H3 或任意代理支持 UDP |
| `session-resumption` | 始终支持；`lk_client_builder_set_session_resumption_json` |
| `quic-connect-timeout` | 始终支持此配置入口，不表示已编译 H3 |
| `optional-phase-timeouts`、`optional-total-timeout`、`read-idle-timeout` | 始终支持；阶段/总 deadline 的启停与 body idle 配置 |
| `debug-registry` | 需要同名 FFI 开发 feature；不是生产能力要求 |

并非所有导出函数都有 capability 名称。例如 TAI JSON、MASQUE config 和 telemetry 应结合
发布构建信息及具体函数返回值判断。`lk_metrics_snapshot` 符号始终存在，未启用
`telemetry` 时返回全零，不能把零值当作“没有请求发生”的证据。

Rust/C 功能对应关系见[配置入口索引](../reference/configuration.md)。WebSocket、流式上传、
自定义 Middleware、请求幂等性覆盖等 Rust 功能尚未全部通过 C ABI 暴露。

## JSON 与字符串所有权

| 输出 | 所有权与终止符 |
|---|---|
| `lk_session_get_*cookies*_json` 等借用 getter | 由 handle 持有的 NUL 结尾字符串；复制后使用，不调用 free |
| `lk_*_copy_attempt_summary_json` | 调用方提供 buffer，长度不含且不写末尾 NUL |
| `lk_preset_export_json` | 调用方提供 buffer，所需长度不含 NUL，但容量须为 `length + 1` |

每个函数的有效期和长度约定独立，不能统一套用同一种字符串释放逻辑。同步/异步读取的
chunk view 也是借用数据，下一次修改性操作前需复制；`lk_stream_copy_chunk` 可复制当前
chunk 到调用方 buffer。

## 绑定作者最低验证

```bash
cargo test -p lkrequest-ffi
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
```

修改导出面后还应重新生成 header、比较 ABI，并运行 `lkrequest-ffi/tests/c_smoke.c`。不要提交生成的 `lkrequest.h`。
