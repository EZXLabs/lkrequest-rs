# HTTP 协议策略

lkrequest 支持 H1、原生 H2，以及 feature-gated H3/QUIC。协议策略表达“使用哪条传输路径”，fingerprint profile 表达“该路径在线缆上如何序列化”，两者不要混为一项配置。

## 能力矩阵

| 模式 | Feature | 连接 | 典型用途 |
|---|---|---|---|
| H1 | 默认 | TCP + TLS | 兼容旧服务、明确禁用 multiplexing |
| H2 | 默认 | TCP + TLS + ALPN | 默认 TCP HTTP、多路复用和 H2 指纹 |
| H3 | `quic-h3` | UDP + QUIC TLS | H3 指纹、Alt-Svc upgrade、QUIC 研究 |

## Session 便捷策略

```rust,ignore
let h1 = client.session().http1_only().build();
let h2 = client.session().http2_only().build();
let strict_h3 = client.session().http3_only().build();
let fallback_h3 = client.session().http3_with_fallback().build();
```

- `http1_only()` 禁止 H2/H3。
- `http2_only()` 禁止 H1 fallback 和 H3。
- `http3_only()` 要求 H3，失败直接返回错误。
- `http3_with_fallback()` 在允许的 QUIC/H3 建连失败上回退 TCP-based HTTP。

H3 request 已经发送后发生的 stream/header/body 错误不会自动改用 H2 重放，因为这不能证明原请求未被服务端处理。

## 默认发现与升级

没有 request/session override 时，使用 Client/preset 的 `ProtocolPolicy`：

1. 先复用已有健康连接；
2. 从 DNS HTTPS record 或响应 `Alt-Svc` 学习 H3 可用性；
3. 根据 acquisition/upgrade policy 建立或探测 QUIC；
4. 根据 fallback policy 处理建连失败；
5. Broken QUIC tracker 在 cooldown 内避免反复尝试已失败路径。

默认/自动模式不保证首个请求直接使用 H3。只有明确的 H3-only 策略才把“必须使用 H3”作为成功条件。

## 单次请求覆盖

```rust,ignore
use lkrequest::PreferredHttpVersion;

let response = session
    .get("https://example.com")
    .preferred_http_version(PreferredHttpVersion::Http2Only)
    .send()
    .await?;
```

request override 只影响该请求。频繁在同一 Session 混用互斥策略可能降低池复用效果，排障时也更难区分 preset、Session 与 request 配置。

## Alt-Svc 与 Broken QUIC

- Alt-Svc 按 origin 缓存，不能把一个域名的 H3 advertisement 用于另一个域名。
- QUIC handshake 失败会按 policy 记录 cooldown；透明代理或 UDP 网络恢复后，可选择更快恢复的 `BrokenQuicPolicy::Resilient`。
- H3 成功建立不代表每个 request 都可重放；retry 仍受幂等性规则约束。
- 0-RTT 只在有可恢复 session 且请求被判定为 replay-safe 时尝试。

启用 H3 示例：

```bash
cargo run -p lkrequest --features quic-h3 --example basic_h3 -- https://cloudflare-quic.com/
```

该命令属于公网请求，应只在允许网络访问的环境运行。
