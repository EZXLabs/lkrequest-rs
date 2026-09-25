# 功能与协议规格

本页描述当前 workspace 的用户可见能力。精确类型和参数以 rustdoc 为准。

## Cargo features

| Feature | 默认 | 类型 | 影响 |
|---|---:|---|---|
| `quic-h3` | 否 | protocol | 启用 `lkquic`、`lkh3`、`lktls-quic`、Quinn 和 H3 API/示例 |
| `masque` | 否 | experimental protocol | 启用 MASQUE（RFC 9298 CONNECT-UDP）代理与 `lkmasque`；蕴含 `quic-h3`。MASQUE 专用 API 和代理互操作行为仍可能调整 |
| `doh` | 否 | DNS | 启用内置 Google/Cloudflare/Quad9 DoH resolver |
| `telemetry` | 否 | operations | 启用连接、请求和带宽计数 |
| `synthetic-fp` | 否 | research | 启用 synthetic recombine/full randomization；不代表真实浏览器 |

### 兼容与开发 feature

| Feature | 类型 | 说明 |
|---|---|---|
| `h2-native` | deprecated compatibility | `0.2.2` 为避免旧 Cargo 配置解析失败而保留的 no-op alias；HTTP/2 始终使用 `lkh2`。将在 `0.3.0` 从 `lkrequest` 和 `lkh2` 完全删除，现在应从用户的 feature 列表中移除 |
| `network-e2e` | test-only | 编译公网集成测试辅助面，不增加生产能力 |
| `bench-internals` | internal | benchmark 诊断入口，不属于稳定用户 API |

## HTTP 与 TLS

| 能力 | 状态 | 说明 |
|---|---|---|
| HTTP/1.1 | 支持 | 可强制 H1-only |
| HTTP/2 | 支持、默认编译 | 原生 `lkh2`，支持 SETTINGS/header/priority/HPACK 指纹控制 |
| HTTP/3 | 可选 | 需要 `quic-h3`，支持 strict、fallback 和自动发现策略 |
| TLS 1.2 / 1.3 | 支持 | 具体版本、cipher 和 extension 由 profile 决定 |
| ECH | 支持 | 可从 HTTPS DNS record 获取配置；rejection 不降级为泄漏真实名称的明文路径 |
| ALPS / cert compression | profile-dependent | 由目标 preset 决定 |
| TLS key log | 支持 | 用于受控诊断，产物高度敏感 |
| mTLS server request | 协议支持 | 用户侧客户端证书配置能力需按具体 API/FFI surface 验证，不能假设自动提供客户端证书 |

## 请求与响应

- async 与 blocking Client/Session/Request；
- GET、POST、PUT、DELETE、HEAD、PATCH、OPTIONS 和自定义 method；
- query、typed/string headers、header order、basic/bearer auth 和 Cookie；
- Cookie jar 读取：名值对、带完整属性的 `CookieInfo`、跨域名列出全部未过期 Cookie，以及按 Chrome 规则排序的 `Cookie` 头；
- bytes、text、JSON、form、multipart 内存请求体；
- 普通完整响应和 streaming response；
- Brotli、gzip、deflate、zstd 解压；
- redirect history、status error、structured diagnostics；
- middleware、retry policy、idempotency 和资源限制；
- WebSocket、preconnect 和 prefetch。

Rust API 支持通过 `body_reader(reader, length)` 和 `body_stream(stream, length)` 流式上传；同步接口支持 `std::io::Read`。覆盖 H1/H2，以及启用 `quic-h3` 后的 H3。multipart、JSON、form、`body()` 和 C ABI 上传接口仍使用内存 body。参见[流式上传](../guides/requests/streaming-upload.md)。

## 网络与代理

| 能力 | 状态 |
|---|---|
| Direct TCP/UDP | 支持 |
| HTTP CONNECT | 支持，含 Basic auth |
| SOCKS5 local DNS | `socks5://` |
| SOCKS5 remote DNS | `socks5h://` |
| Multi-hop proxy chain | 支持 |
| Dynamic proxy provider | 支持 |
| ProxyPool / SessionPool | 支持 |
| SOCKS5 UDP relay | 需要 `quic-h3` 且代理支持 UDP ASSOCIATE |
| MASQUE CONNECT-UDP | 实验性；`masque://` 需要 `masque` feature，且代理必须支持 H3 与 HTTP Datagram。只中继 UDP（QUIC/H3），远程 DNS，不能作为代理链的一跳，外层连接不带浏览器指纹。详见[代理与 DNS](../guides/networking.md) |
| 代理认证凭据形态 | `UserPass`（Basic / SOCKS5 RFC 1929）、`Http { scheme, credentials }`（Preshared/PrivateToken/Bearer 等，仅 header 代理）、`Custom`（Rust-only） |
| 代理认证头字段名 | `Proxy-Authorization`（默认）或 `Authorization`，仅对 header 代理有效 |
| System DNS | 默认；相同并发查询 singleflight |
| Positive DNS cache | 可选、显式配置 |
| Custom UDP/TCP DNS | 支持 |
| DoH | 需要 `doh` |
| HTTPS/SVCB records | Hickory resolver 路径支持 |

## Rust 与 FFI 差异

- Rust API 是完整能力入口，底层 profile 和策略类型可直接组合。
- FFI 覆盖 Client、Session、Request、Response、streaming、Pool、Multipart、DNS、日志和 randomization 的高价值入口。
- FFI 使用 opaque handle 和内部 Tokio runtime；不向绑定暴露 Rust Future。
- 新增 Rust API 不自动等于 FFI 已暴露，绑定作者应查询 header 和 capability smoke test。
- 代理认证的 `Custom` 形态是 Rust-only：trait object 无法跨 C ABI。FFI 覆盖 `masque://` URL 解析、用户名/口令与静态 HTTP auth-scheme 凭据，以及认证头字段名选择。
- MASQUE 外层连接的配置（`MasqueOuterConfig`）在 FFI 侧是 `lk_masque_config_t` 句柄：信任锚（`lk_masque_config_add_ca_certs_pem` / `..._add_ca_cert_der`）、`use_native_certs`、`verify`、`server_name`，以及隧道回收的 `tunnel_idle_timeout` / `max_idle_tunnels`。挂载入口有两个——`lk_client_builder_set_masque_config`（请求路径）与 `lk_proxy_pool_builder_set_masque_tunnel_probe` / `lk_session_pool_builder_set_masque_tunnel_probe`（健康检查的 CONNECT-UDP 探测）。全部需要 `masque` feature；没有它时符号仍在，但一律报错，所以 header 不随 feature 改变形状。
- **`lk_masque_config_set_verify` 是最后手段，不是私有 CA 的解法。** 私有 CA 用上面那两个信任锚入口就能完整表达，且保留认证。它存在是因为假阴性不分语言：证书根本无法校验时（例如证书上的名字在该环境不解析），没有这个开关的 C 调用方只剩"健康代理被拉黑"而无路可走，而 Rust 侧有 `masque_verify(false)`。风险与 Rust 侧相同，且与 `lk_client_builder_set_verify`（目标站点那一跳）互不影响。`bind_addr`、`alpn`、`inbox_depth` 未暴露，那只是还没有调用方，不是安全考量。
- FFI header 是构建产物，不在 Git 中跟踪。
