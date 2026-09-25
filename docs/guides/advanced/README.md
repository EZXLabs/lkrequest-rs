# 高级应用

高级应用从具体任务出发，介绍普通请求之外的特殊接口和组合方式。先选择下面的场景并运行最小示例；只有在需要判断状态生命周期时，再阅读 [Client、Session 与 Request](../object-model.md)。

## 场景导航

| 场景 | 推荐页面 | 核心对象 |
|---|---|---|
| 高并发、多账号、代理轮换 | [SessionPool 与 ProxyPool](high-throughput.md) | `Client`、`SessionPool`、`ProxyPool` |
| 固定代理轮转、动态代理生成、失败切换 | [ProxyPool 轮转与动态生成](proxy-pool.md) | `ProxyPoolBuilder`、`ProxyGuard`、`ProxyProvider` |
| H3 自动升级、强制协议、fallback | [协议发现与回退](protocol-discovery.md) | `ProtocolPolicy`、Alt-Svc、BrokenQuicTracker |
| 修改 TLS/H2/H3 指纹 | [自定义指纹与验证](../../development/fingerprint-research.md) | preset、profile、capture、fixture |
| 连接级顺序变化、跨层 synthetic identity | [指纹随机化](randomization.md) | `Randomize`、`Layers`、`NegotiabilityFloor` |
| 统一注入审计、改写请求、检查响应 | [Middleware](middleware.md) | `Middleware`、洋葱顺序、短路中止 |
| 请求阶段耗时、指标与解密诊断 | [诊断与可观测性](observability.md) | diagnostics、telemetry、tracing、key log |

## 通用原则

1. 先用完整 preset 和默认 Session 完成最小请求；
2. 再选择身份生命周期：长期 Session、池化 Session 或每任务新 Session；
3. 明确 retry、redirect、0-RTT 和 streaming 是否允许重放；
4. 只在需要时覆盖协议策略或底层 profile；
5. 对性能、指纹和业务成功分别保留证据，不能互相替代。

## 其他高级能力

| 能力 | 页面 |
|---|---|
| WebSocket 握手、收发与关闭 | [WebSocket](../websocket.md) |
| 请求认证、自定义 CA、证书校验 | [认证与证书](../auth-and-certificates.md) |
| 响应体上限、HSTS、会话恢复与票据分区 | [资源限制与安全边界](../limits.md) |
| `HttpIntent`、`preconnect()` 与 `prefetch()` | [协议发现与回退](protocol-discovery.md) |
| multipart 与流式上传 | [请求体](../requests/bodies.md)、[流式上传](../requests/streaming-upload.md) |
| DNS resolver 与 DoH | [代理与 DNS](../networking.md) |

一点需要单独记住：

- `send_streaming()` 用于增量读取响应，但不执行普通请求的完整 redirect/retry 流程。

以及两条容易混淆的边界：

- 固定代理列表与动态代理 provider 的失败语义不同，不应复用同一套拉黑逻辑；
- synthetic fingerprint 不是浏览器 preset，不能继承 preset 的 verified 状态。

具体类型与方法以 rustdoc 为准。只有贡献代码或直接维护底层协议时，才需要阅读开发者区的 [Crate 功能与选型](../../development/crates.md)。
