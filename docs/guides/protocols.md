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

默认模式下，H3 request 已经发送后发生的 stream/header/body 错误不会自动改用 H2 重放，因为这不能证明原请求未被服务端处理。显式的 `H3RetryMode::Chrome155ProtocolErrors` 可对有限缓冲请求启用响应头之前的协议错误重试；它仍遵守协议回退限制，详见[请求配置](requests/README.md#显式-http3-兼容重试)。

## 默认发现与升级

没有 request/session override 时，使用 Client/preset 的 `ProtocolPolicy`：

这包括 preset 的 `Race` 获取策略。只有显式调用旧版 `protocol_selection_policy(Deterministic)` 时，才会把该竞速策略转换为确定性选择。

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

Chrome 155 QUIC preset 在已完成的 PSK 握手正常拒绝早期数据时，可保留原连接和请求流，以 1-RTT 重传。该路径要求实际早期票据的 ALPN 与最终协商结果一致、没有 HRR，且服务端的新传输参数兼容；无法确认这些条件时仍使用原有恢复方式。TLS 的早期数据接受结果仍为拒绝，这次传输层恢复不占用额外的 HTTP/3 协议错误重试次数。

自定义配置可将 `QuicProfile.packetization.reuse_rejected_0rtt_streams` 设为 `false`，保留拒绝后重建连接的行为。旧版 preset 和缺少该字段的序列化配置默认关闭。上述恢复不改变请求原有的幂等性与可重放性检查。

Chrome 155 还默认启用两个独立的恢复设置：`chrome_rtt_quantization` 使用对应 Chromium 版本的平滑 RTT 和偏差舍入方式；`queue_pto_while_blocked` 允许已确认的 1-RTT 连接在 socket 写阻塞时排队真实 PTO 重传，并按 FIFO 恢复写入。这条排队路径不会推进尚未发送的应用数据。自定义配置可分别关闭这两个选项，旧版 preset 和缺少字段的配置保持关闭。

Chrome 155 默认开启 `discard_blocked_close`：客户端在握手已确认后因应用协议错误等原因主动关闭时，丢弃因写阻塞而未发送的 `CONNECTION_CLOSE`，不会在 socket 恢复可写后补发。可写时的正常关闭仍会发送关闭包，关闭通知和清理定时器继续生效。默认配置、旧版 preset、握手未确认、服务端及传输错误关闭保留原有策略；自定义配置可将该字段设为 `false` 以保留新关闭包的重试行为。

`chrome_pto_timing` 在握手已确认且已有 RTT 样本的 1-RTT 恢复定时器中，保留与已设置截止点相差不足 1 毫秒的更新；恰好 1 毫秒时会更新。PTO 和基于时间阈值的丢包检测共用这条更新规则，取消或已触发的定时器仍会重新设置。丢包阈值、候选截止点的丢包计算公式和其他定时器保持原有行为。

这些选项控制协议状态和恢复算法，不保证不同系统时钟、输入历史或线程调度下的发送时刻完全相同。

`H3Profile.defer_qpack_stream_prefixes` 将 QPACK 编码器和解码器流的类型前缀延迟到各自首条指令发送时；没有指令的空闲 QPACK 流不发送前缀字节。控制流 SETTINGS 和请求仍正常发送，流 ID 的分配方式不由该选项控制。Chrome 155 preset 默认开启，默认 profile、旧版 preset 和缺少该字段的序列化配置保持关闭。自定义 profile 可显式设置该布尔值；新连接和 0-RTT 连接均应用该设置。

启用 H3 示例：

```bash
cargo run -p lkrequest --features quic-h3 --example basic_h3 -- https://cloudflare-quic.com/
```

该命令属于公网请求，应只在允许网络访问的环境运行。
