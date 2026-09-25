# 故障排查

排障时先保留结构化 Error、`phase()`、代理类型、实际协议、feature 和是否发生 retry/fallback。不要只截取错误字符串的最后一行。

## 错误到动作

| 判断 | 常见含义 | 首要动作 |
|---|---|---|
| `is_dns()` | resolver、DNS server 或目标记录失败 | 记录 resolver 配置，分别验证 hostname 与代理 hostname |
| `is_tcp()` | 地址不可达、连接拒绝、拨号超时 | 检查实际候选 IP、IPv4/IPv6、代理入口和连接预算 |
| `is_proxy_tunnel()` | CONNECT/SOCKS5/MASQUE 握手、认证或 relay 失败 | 检查 scheme、默认端口、credential 编码和代理日志；MASQUE 见下文专节 |
| `is_tls_handshake()` | 证书、ALPN、TLS alert、ECH 或 mTLS | 使用相同出口对比 `curl -v`，必要时启用 key log |
| `is_timeout()` | DNS/TCP/TLS/TTFB/total 某阶段超时 | 查看 `phase()` 与 timeout 配置，不要只扩大总超时 |
| `is_quic_handshake_failure()` | UDP/QUIC 建连失败 | 验证直连和相同代理路径的 UDP；检查 fallback policy |
| `is_h3_request_failure()` | 已建 QUIC 上的 H3 request 失败 | 不假设可安全 H2 重放；检查 stream 与幂等性 |
| `Error::TooManyRedirects` | redirect loop 或上限过低 | 查看 `redirect_history()`，检查 scheme/host 变化 |
| `Error::ResourceLimitExceeded` | body、headers 或连接资源超限 | 确认响应规模，再调整对应 ResourceLimits |

## TLS handshake 提前关闭

出现 `connection closed during TLS handshake` 时：

1. 用相同目标和相同代理执行 `curl -v`，确认 CONNECT 是否真正返回成功。
2. 区分 proxy tunnel 提前关闭和目标 TLS alert；HTTP 200 CONNECT 不代表后续 tunnel 一定可用。
3. 检查目标是否要求客户端证书；收到 CertificateRequest 后空证书可能被服务端拒绝。
4. 检查 ALPN、SNI、ECH 和 preset 是否适合目标。
5. 如可控，启用 TLS key log 并抓取握手；不要公开 key log。

## Proxy early EOF 或认证失败

- 使用 `ProxyConfig::parse()` 显式验证 URL，避免 Session builder 静默忽略无效字符串。
- credential 中的特殊字符必须进行 URL percent-encoding。
- `socks5` 与 `socks5h` 的 DNS 位置不同；先确认代理是否接受 domain target。
- HTTP CONNECT 的 407 表示需要代理认证；检查 retry 的第二次 CONNECT 是否携带凭据。
- rotating proxy username 变化会形成不同 proxy identity，连接池和 cooldown 不应跨身份复用。

## H2 并发停滞

- 检查远端 `MAX_CONCURRENT_STREAMS`，不要把 stream limit 当作本地 task deadlock。
- 检查 `max_pending_h2_requests()` 是否过小或队列已经占满。
- 查看物理连接预算；Session 不会无限创建新连接绕开限制。
- GOAWAY、REFUSED_STREAM、EOF 和 stale pooled connection 的安全 retry 条件不同。
- 对 POST/PUT 等请求，除非明确幂等或可证明尚未处理，否则不要自动重放。

## QUIC/H3 timeout

1. 确认编译时启用了 `quic-h3`。
2. 直连测试目标 UDP，再通过与生产相同的代理/隧道路径测试。
3. SOCKS5 场景检查 UDP ASSOCIATE 和 relay 地址，而不只是 TCP SOCKS5 成功。
4. 检查 Alt-Svc/HTTPS DNS 是否真正提供 H3 candidate。
5. 检查 Broken QUIC cooldown；网络恢复后旧 Session 可能仍处于隔离窗口。
6. 使用 `http3_only()` 区分“必须 H3 的失败”和 fallback 后成功。

## MASQUE 隧道建立失败

MASQUE 路由（`masque://`，需要 `masque` feature）上的失败要先分清失败在哪一跳：**到代理的外层 HTTP/3 连接**、**CONNECT-UDP 隧道协商**，还是**代理到目标的那一段**。下面几类的判据和动作不同：

| 现象 | 结构化信号 | 常见含义 | 首要动作 |
|---|---|---|---|
| 代理不可达 | `ProxyErrorKind::IoError`，消息含 `did not resolve` 或以 `MASQUE outer connection to …` 开头；或 `is_timeout()` 且 `phase()` 为 proxy tunnel | DNS 解析不到代理、UDP 到代理被阻断、外层 TLS 校验失败 | 直连测试代理端口的 UDP/QUIC 可达性；确认 `use_native_certs` 或 `extra_roots` 覆盖了代理证书链 |
| 没有可用信任锚 | `Error::InvalidConfig`，消息为 `has no trust anchors` | 既关掉了 `use_native_certs` 又没给 `extra_roots` | 私有 CA 部署必须显式提供 `extra_roots`；这是配置错误，不会进入任何冷却 |
| 认证失败 | `ProxyErrorKind::AuthenticationFailed`（代理返回 401 或 407） | 凭据被拒，或字段名/scheme 与代理期望不符 | 检查凭据形态（`Basic` vs `<scheme> <credentials>`）；试着把认证头从默认的 `Proxy-Authorization` 切到 `Authorization`；确认 `auth` 与 `credential` 没有同时设置 |
| 代理拒绝 connect-udp | `ProxyErrorKind::TunnelRefused { status_code }`（其余 4xx/5xx），消息含 `refused CONNECT-UDP with status` | 代理工作正常但不接受这次请求：目标不在允许范围、配额用尽、后端故障 | 看 `status_code`：4xx 多为“不是这个目标”，5xx 多为代理自身故障。换目标或换代理分别验证 |
| 代理协议不合规 | `ProxyErrorKind::ProtocolError` | 响应不满足 RFC 9298 §3.5 所引 RFC 9297 §3.2 的要求：状态是 204/205/206，或响应带了 `content-length` / `content-type` / `transfer-encoding`（错误消息会写明是哪一个）。也可能是外层 datagram 容量低于 QUIC 要求的 1200 字节 | 前者说明代理把这条响应当成带 body 的普通响应发了，其数据流不是 capsule 流，需要代理侧修正；容量不足的消息会写明实际字节数，说明外层路径 MTU 太小 |

注意**缺少 `capsule-protocol: ?1` 不在此列**：该响应头在 RFC 9297 §3.4 只是 SHOULD，`connect-udp` 的 2xx 响应已经通过 upgrade token 让 Capsule Protocol 生效，所以省略它的代理照常可用，只会留下一条 `masque.capsule_protocol_header_absent` 的 debug 日志。
| 目标不可达 | 没有隧道阶段的错误，`masque.tunnel_open` 已经出现过；最终返回的却常常是“只中继 UDP”的 `ProxyErrorKind::ProtocolError`（见下） | 隧道正常，代理到目标那一段不通，或目标根本不支持 QUIC | 用同一代理换一个已知支持 H3 的目标对比；以 tracing 里第一条失败为准，不要以最终错误消息为准 |

### 隔离范围决定了下一次请求的表现

隧道失败会记录隔离，隔离的粒度取决于失败类型：

- **4xx 拒绝只隔离该 origin**。RFC 9298 §3.1 要求代理先解析并评估目标再作答，所以 `403` 意味着“不是这个目的地”，而代理本身完好。为它隔离整条路由会让其他所有 origin 白白失去 H3 通路。
- **其余失败（含 5xx、401/407、外层连接失败、协议不合规）隔离整条路由**，记为 `BrokenReason::MasqueTunnelUnavailable`。这些都不说明“最先排到队首的那个 origin”有任何问题。
- **配置错误（`Error::InvalidConfig`）不记录任何隔离**：它在每条路由上都会一样地失败，靠改配置解决，等冷却窗口没有意义。

路由被隔离后，同一 Session 对该代理的后续请求在冷却窗口内（默认 30 分钟，由 `BrokenQuicConfig::route_cooldown` 控制）不再尝试隧道，而是短路到“该代理只中继 UDP、不能承载 TCP”这个明确错误——**第二次起看到的错误消息和第一次不同**，这是预期行为，目的是不必每次都付一遍隧道超时。要看原始原因，请看第一次失败或 tracing 日志。

### MASQUE 路由不回退

- 隧道失败**不回退直连**，即便开启了 `proxy_fallback_direct`：静默直连会泄露源地址，而那正是配置 MASQUE 要隐藏的东西。
- 隧道建立失败**也不回退 H2**：这类错误不属于 QUIC 握手类，代理错误原样返回给调用方。
- H1/H2 请求（`http1_only()`、`http2_only()`、`http://` 明文目标）在 MASQUE 路由上直接以 `ProxyErrorKind::ProtocolError` 失败，消息说明需要 HTTP CONNECT 或 SOCKS5 代理。
- 隧道之后才发生的**内层** QUIC 握手失败属于握手类，默认 fallback 策略（`AllowFallback`）会尝试转向 TCP；那次尝试会立刻撞上同一个“只中继 UDP”的错误并终止。结果是安全的（不会直连），但最终返回给调用方的错误消息**不是**内层握手的原因。要定位真实原因，看 tracing 里的第一条失败，或把策略设为 `FallbackPolicy::NoFallback` / 用 `http3_only()` 让原始错误直接浮出。

### 可用的诊断信号

- `Error::phase()` 为 `ConnectionPhase::ProxyTunnel`（`is_proxy_tunnel()` 为真）：失败发生在隧道建立阶段，而不是目标握手阶段。
- `BrokenReason::MasqueTunnelUnavailable`：路由级隔离的原因。它和 SOCKS5 的 `ProxyUdpUnavailable` 刻意区分开，因为两者的代码路径和修复方式完全不同。
- `masque.*` 前缀的 tracing 事件。判读隧道生命周期时最有用的几个：`masque.outer_connected`（外层连接建立）、`masque.tunnel_open`（隧道就绪）、`masque.tunnel_failed`、`masque.tunnel_closed`、`masque.tunnels_reaped`（回收）、`masque.datagram_dropped_over_capacity` 与 `masque.payload_over_protocol_max`（两种超限，含义不同）、`masque.capsule_stream_failed` / `masque.request_stream_lost`（外层流中断）。
- 会话层事件：`quic.masque_connect_prepare`、`quic.masque_tunnel_failed`。
- ProxyPool 主动探测的事件：`proxy_pool.health_check_skipped_masque`（探测未开启）、`proxy_pool.health_check_skipped_masque_no_outer_config`（开了探测但没给外层配置，见 [ProxyPool 轮转与动态生成](advanced/proxy-pool.md)）。

tracing 与日志的接入方式见[诊断与可观测性](advanced/observability.md)。

## 提交 issue 时提供

- lkrequest commit 或版本、Rust 版本、OS 和 target triple；
- 启用的 Cargo features；
- 使用的 preset、Session 协议策略和 proxy scheme；
- 完整 Error debug 输出、`phase()`、status 和 negotiated version；
- 最小复现代码及是否需要公网；
- 脱敏后的 tracing 日志；
- 如涉及 fingerprint，提供有序字段或 packet-level 差异，并说明浏览器版本、平台和采集日期。

不要附带 proxy 密码、Cookie、Authorization、TLS key log、原始业务抓包或未脱敏 URL。
