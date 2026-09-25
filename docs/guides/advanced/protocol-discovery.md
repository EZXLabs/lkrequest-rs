# 协议发现与回退

高级协议策略用于控制 H1/H2/H3 的获取和回退，不用于选择不同的 H2 实现。HTTP/2 始终由 `lkh2` 提供。

## 常用策略

```rust,ignore
let h1 = client.session().http1_only().build();
let h2 = client.session().http2_only().build();
let strict_h3 = client.session().http3_only().build();
let fallback_h3 = client.session().http3_with_fallback().build();
```

| 策略 | 成功条件 | 适用场景 |
|---|---|---|
| H1-only | 必须使用 H1 | 兼容性定位、禁用 multiplexing |
| H2-only | 必须使用 H2 | H2 fingerprint 验证和稳定 TCP path |
| H3-only | 必须建立 H3 | QUIC/H3 测试；失败直接返回错误 |
| H3 with fallback | 优先 H3，允许特定建连失败回退 | 普通支持 H3 的业务请求 |
| 自动模式 | 根据已知能力选择 | 长期 Session 和浏览器式升级 |

## 自动 H3 生命周期

1. 首次访问复用已有连接；没有信息时通常先走 TCP/H2；
2. DNS HTTPS/SVCB 或响应 Alt-Svc 提供 H3 endpoint；
3. Session 后续请求尝试 QUIC/H3；
4. 成功连接进入池并复用；
5. 建连失败由 BrokenQuicTracker 记录 cooldown，避免每个请求重复探测；
6. policy 允许时回退到 TCP-based HTTP。

Alt-Svc 指定的是连接目标，不会改变 origin、SNI 或证书身份。不能把一个 origin 的 advertisement 复用到另一个 origin。

## 声明请求意图

`HttpIntent` 表达"这个请求希望怎么拿到协议"，可以设在 Session 上作为默认，也可以按请求覆盖：

| 取值 | 含义 |
|---|---|
| `H2Only` | 禁用 QUIC/H3，留在 TCP 路径 |
| `H3Only` | 要求 QUIC/H3，不静默降级 |
| `AcquireH3WhenViable` | 当 H3 被广告或可行时去获取 |
| `ReuseExistingProtocol` | 复用当前健康的协议，不额外付出获取 H3 的代价 |

```rust,ignore
// Session 默认：复用已有协议，避免每次都尝试升级
let session = client.session().http_intent(HttpIntent::ReuseExistingProtocol).build();

// 单个请求：这次明确要 H3，失败就报错而不是回退
let response = session
    .get("https://example.com/asset")
    .http_intent(HttpIntent::H3Only)
    .send()
    .await?;
```

`PreferH3` 和旧的复用取值已标记为废弃，分别用 `AcquireH3WhenViable` 和
`ReuseExistingProtocol` 替代。

## 预热连接

首个请求要承担 DNS、TCP、TLS 和 ALPN 的全部耗时。已知接下来要访问哪些站点时可以提前预热：

```rust,ignore
// 只建连接，不发请求
session.preconnect("https://api.example.com").await?;

// 并发预热多个目标，返回每个目标的结果
for result in session.preconnect_many(&[
    "https://api.example.com",
    "https://cdn.example.com",
]).await {
    if !result.success {
        eprintln!("{} 预热失败，耗时 {:?}：{:?}", result.url, result.duration, result.error);
    }
}
```

`preconnect` 只建立连接；`prefetch` 会发送真实的 HEAD 请求，因此会在服务端留下访问记录，
也会触发风控计数。两者返回的 `PrefetchResult` 带 `url`、`success`、`duration` 和
`error`，可用来判断某个目标是否值得继续。预热的连接进入 Session 的连接池，随后的请求
直接复用。

## 重放边界

- H3 建连前失败可以按 policy 回退；
- request 已发送后的 stream、header 或 body 错误不能自动假设安全重放；
- 0-RTT 只应用于有可恢复 session 且被判定为 replay-safe 的请求；
- `POST` 等非幂等请求应由调用方明确判断 idempotency；
- streaming API 不执行普通请求的完整 redirect/retry pipeline。

## 排障顺序

1. 使用 H2-only 验证 TCP/TLS 和 origin 本身；
2. 使用 H3-only 暴露真实 QUIC 错误，避免 fallback 掩盖问题；
3. 检查 DNS HTTPS record、Alt-Svc、UDP 路径和代理 UDP 支持；
4. 开启单次 diagnostics，确认 negotiated protocol 和阶段耗时；
5. 最后再恢复自动或 fallback 模式。

基础协议选择说明见 [HTTP 协议策略](../protocols.md)。

