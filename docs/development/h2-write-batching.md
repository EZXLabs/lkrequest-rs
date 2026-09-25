# HTTP/2 Write Batching：性能与指纹边界

本文说明 `h2_dispatch_batch_size` 的用途、性能收益，以及它对浏览器线缆级指纹的影响。该功能是客户端实现层的发送优化，不是 HTTP/2 协议扩展。

## 结论

- 默认值为 `1`，保持原有 fingerprint-sensitive 写入行为。
- 大于 `1` 时，多个已经 ready 的请求可以编码到同一次底层 write 中。
- SETTINGS、HPACK、伪头顺序、stream ID 和 HTTP/2 frame 字节保持不变。
- TLS record 边界、TCP segment 分布和请求发送时序可能明显改变。
- 性能优先且不验证线缆行为时可以启用；浏览器 preset 不应默认启用。
- 即使抓包中的 TCP segment 看起来接近 Chrome，也不能据此证明 TLS record 边界一致。

## 工作方式

默认模式对每个请求生成的 frame group 分别写入：

```text
HEADERS(stream 1) -> write
HEADERS(stream 3) -> write
HEADERS(stream 5) -> write
```

启用 batching 后，driver 在连接已经存在 in-flight stream 时允许其他 producer 运行，收集当前 ready 的请求，并保持顺序编码到一个有界缓冲区：

```text
[HEADERS(stream 1)][HEADERS(stream 3)][HEADERS(stream 5)] -> write
```

当前实现同时受两个边界限制：

- 请求数量不超过配置的 batch size；
- 编码后的累计缓冲区不超过 64 KiB。

达到任一边界就立即写出。不同 H2 连接之间不会 batching，因此不同 Session 的独立连接也不会互相合并。

## 不变的协议指纹

batching 不改变 frame 的协议内容：

| 指纹维度 | 是否改变 |
|---|---|
| TLS ClientHello / JA3 / JA4 | 否 |
| H2 SETTINGS 值与顺序 | 否 |
| WINDOW_UPDATE / PRIORITY | 否 |
| 伪头和普通 header 顺序 | 否 |
| HPACK 编码结果 | 否 |
| stream ID 和 frame 顺序 | 否 |

这些结论只表示序列化 frame 内容不变，不表示完整网络行为不变。

## 可能改变的行为指纹

一次 AsyncWrite 通常会进入 TLS 层和内核 TCP 层，因此调用边界变化可能影响：

- TLS application-data record 的数量和大小；
- 多个 H2 frame 是否出现在同一个 TLS record；
- TLS record 到 TCP segment 的映射；
- TCP payload 大小分布和小包数量；
- 并发 stream 的 burst 形态；
- frame、ACK 和响应之间的时间间隔；
- 代理或服务端能够观察到的调度节奏。

因此，它对常见的静态 H2 fingerprint hash 可能不可见，但对 TLS record、包级和时序型检测是可见的。

## 与 TCP_NODELAY 的区别

`TCP_NODELAY` 主要改变内核是否因为 Nagle 算法等待小数据；write batching 则直接改变应用层提交给 TLS/socket 的 write 边界。

lkrequest 当前的 TCP 行为是：

- 新建 TCP 连接时默认设置 `TCP_NODELAY=true`，与交互式浏览器 HTTP 流量的低延迟需求一致；
- 如果 `TcpFingerprint` 显式配置 `tcp_nodelay=false`，fingerprint 配置会在连接建立后覆盖默认值；
- 未配置 TCP fingerprint 不再表示启用 Nagle，而是继续使用 `TCP_NODELAY=true`；
- 该默认值适用于 H1 和基于 TCP 的 H2，不影响基于 UDP 的 HTTP/3/QUIC。

默认启用的主要原因是，小型 H2 HEADERS、DATA 和控制帧可能与 delayed ACK 共同触发明显等待。2026-09-05 的本地 A/B 中，仅修正 `TCP_NODELAY` 就消除了约 10–25 ms 的 p99 延迟断崖。完整复现和修正后数据见 [HTTP/2 性能差异诊断](https://github.com/EZXLabs/lkrequest-rs/blob/main/tools/http-client-bench/DIAGNOSIS-2026-09-05.md)。

`TCP_NODELAY=true` 不等于“每次 write 对应一个 TCP 包”。TLS、操作系统发送缓冲区、TCP segmentation offload 和网卡仍然可能合并或拆分数据。它也不改变 TLS ClientHello、H2 SETTINGS、HPACK 或 frame 字节，但可能改变小包数量、segment 边界及发送时序，因此仍属于可观察的行为指纹。

需要复现特殊网络栈行为时，可以显式覆盖：

```rust,ignore
use lkrequest::tcp_fingerprint::TcpFingerprint;

let fingerprint = TcpFingerprint::default().with_tcp_nodelay(false);
```

除非已有对应浏览器和操作系统版本的真实抓包证据，否则浏览器 preset 不应将其改为 `false`。

所以通常有以下风险顺序：

```text
协议 frame 内容变化 > write batching > TCP_NODELAY 开关
```

这里的顺序仅表示对当前项目线缆行为的直接影响程度，不表示所有检测系统都会采用相同权重。

## 与 Chromium 行为的关系

Chromium 的 HTTP/2 写循环通常从发送队列取出一个 frame 并执行一次 socket write；同步完成时继续处理下一个 frame。TLS 层、操作系统和网卡仍可能把连续 write 聚合成较少的 TCP segments。

lkrequest 的 batching 模式是在 H2 driver 层主动把多个请求编码到同一个 buffer，因此不能仅凭最终 TCP 包数量接近 Chrome 就宣称 Chrome-faithful。必须继续验证 TLS record 边界和发送时序。

## 多 Session 场景

优化发生在每条 H2 连接内部：

| 场景 | 预期收益 |
|---|---|
| 1 Session × 32 并发 | 高，单连接容易积累 ready 请求 |
| 4 Session × 8 并发 | 中等 |
| 8 Session × 4 并发 | 较低 |
| 32 Session × 1 并发 | 接近无收益 |

如果 Session 使用不同代理或独立连接，它们不能跨 socket batching。此时系统瓶颈更可能转向连接数量、TLS 握手、端口、代理容量、runtime 调度和服务端连接限制。

## 使用方式

保持指纹敏感的默认行为：

```rust,ignore
let client = Client::builder().build();
```

显式启用性能模式：

```rust,ignore
let client = Client::builder()
    .h2_dispatch_batch_size(64)
    .build();
```

建议仅在以下情况下启用：

- 主要目标是吞吐和尾延迟；
- 不要求复现指定浏览器的 TLS record 和包级行为；
- 同一连接上存在足够的并发 stream；
- 已使用真实负载做过 A/B，而不是只观察 loopback 数字。

## 指纹验证要求

如果希望在浏览器 preset 中使用 batching，至少需要在相同环境中比较真实浏览器与 lkrequest：

1. 固定浏览器版本、操作系统、目标站点和请求序列。
2. 使用相同代理路径，或者全部使用直连。
3. 捕获 TLS key log 和 pcap，避免只比较聚合 hash。
4. 比较有序 H2 frames 和 HPACK 输出。
5. 比较 TLS application-data record 大小和边界。
6. 比较 TCP payload 大小分布、packets/request 和 burst 间隔。
7. 分别覆盖单请求、并发 8、并发 32 和多 Session 场景。
8. 只有证据稳定时，才考虑把特定策略绑定到特定 preset。

h2c benchmark 只能证明 H2 engine 和 TCP 写入性能，不能证明 HTTPS 下的 TLS record 指纹安全。

## 2026-09-05 A/B 摘要

在 Windows loopback h2c、1 KiB 响应、单连接并发 32 的测试中：

- 吞吐从约 33.4k 提升到 47.0k req/s；
- p99 从约 1.40 ms 降到 0.98 ms；
- client-to-server payload packets 从 20,954 降到 2,610；
- 多 Session 下，收益随着每连接并发降低而下降。

这些结果证明 batching 能减少小 write，但不构成浏览器指纹一致性证明。原始方法和结果见 `tools/http-client-bench/AB-BATCHING-2026-09-05.md`。
