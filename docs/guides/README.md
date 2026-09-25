# 使用场景导航

从你要完成的任务开始，而不是从 workspace 架构或底层协议 crate 开始。普通 Rust 用户只需要依赖 `lkrequest`；每个场景页面都会先给出推荐对象和示例，再补充必要概念。

## 我想发送请求

| 目标 | 从这里开始 | 示例重点 |
|---|---|---|
| 完成第一个同步或异步请求 | [快速开始](../getting-started.md) | Cargo 依赖、blocking、Tokio、浏览器 preset |
| 配置 method、header、query 和 body | [请求配置](requests/README.md) | GET、JSON、form、multipart |
| 读取、解码或流式处理响应 | [响应处理](requests/responses.md) | status、headers、text、JSON、streaming |
| 保留 Cookie 和连接复用 | [Client、Session 与连接复用](client-session.md) | 长期 Session、身份隔离、连接预算 |
| 携带 Basic/Bearer 凭据或信任自定义 CA | [认证与证书](auth-and-certificates.md) | `basic_auth`、`bearer_auth`、CA、证书校验 |
| 建立 WebSocket 并收发消息 | [WebSocket](websocket.md) | 握手参数、文本/二进制帧、关闭码 |

## 我需要特定网络路径

| 目标 | 从这里开始 | 示例重点 |
|---|---|---|
| 使用 HTTP、SOCKS5 或代理链 | [代理与 DNS](networking.md) | proxy URL、remote DNS、resolver |
| 强制 H1/H2/H3 或允许回退 | [HTTP 协议策略](protocols.md) | protocol policy、`quic-h3` |
| 根据 Alt-Svc 自动升级 H3 | [协议发现与回退](advanced/protocol-discovery.md) | discovery、fallback、BrokenQuicTracker |
| 轮转固定或动态代理 | [ProxyPool 轮转与动态生成](advanced/proxy-pool.md) | RoundRobin、Random、provider、cooldown |
| 预热连接或声明协议意图 | [协议发现与回退](advanced/protocol-discovery.md) | `preconnect`、`prefetch`、`HttpIntent` |

## 我需要多个身份或高并发

| 目标 | 从这里开始 | 示例重点 |
|---|---|---|
| 多账号并发并保留各自状态 | [SessionPool 与 ProxyPool](advanced/high-throughput.md) | SessionPool、身份生命周期、容量预算 |
| 每个任务使用全新 Cookie 和连接 | [ProxyPool 轮转与动态生成](advanced/proxy-pool.md) | ProxyGuard + fresh Session |
| 统一注入审计、改写请求或检查响应 | [Middleware](advanced/middleware.md) | `Middleware`、洋葱顺序、短路中止 |
| 诊断阶段耗时和连接行为 | [诊断与可观测性](advanced/observability.md) | diagnostics、telemetry、tracing |

## 我需要控制浏览器指纹

| 目标 | 从这里开始 | 示例重点 |
|---|---|---|
| 选择一个已经提供的浏览器版本 | [选择浏览器 preset](choosing-a-preset.md) | preset、feature、验证状态 |
| 查看各协议层验证情况 | [Preset 支持与验证矩阵](../reference/presets.md) | TLS、H2、H3/QUIC、证据等级 |
| 使用 extension shuffle 或 synthetic identity | [指纹随机化](advanced/randomization.md) | `Randomize`、`Layers`、生命周期 |
| 维护或验证自定义指纹 | [自定义指纹与验证](../development/fingerprint-research.md) | capture、profile、fixture、wire evidence |

## 我使用其他语言

从 [C ABI 与其他语言绑定](ffi.md) 开始。FFI 的 Client、Session、Request 和 Response 与 Rust 高层对象对应，但还需要遵守 handle 所有权和异步操作规则。

## 我需要设定防护边界

| 目标 | 从这里开始 | 示例重点 |
|---|---|---|
| 限制响应体大小、响应头数量或最低传输速率 | [资源限制与安全边界](limits.md) | `ResourceLimits`、慢速传输 |
| 控制 HSTS 升级行为 | [资源限制与安全边界](limits.md) | `NoHsts`、`StaticHsts`、`DynamicHsts` |
| 配置 TLS 会话恢复、0-RTT 与票据分区 | [资源限制与安全边界](limits.md) | 恢复策略、重放边界、分区模型 |

## 遇到问题

先查看 [故障排查](troubleshooting.md)，并记录请求场景、feature、协议、代理方式、错误链和最小复现。只有在需要判断状态应该放在哪个对象时，再阅读 [理解 Client、Session 与 Request](object-model.md)。

