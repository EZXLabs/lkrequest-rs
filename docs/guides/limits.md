# 资源限制与安全边界

本页覆盖响应资源上限、请求次数上限、HSTS、TLS 会话恢复，以及会话票据的分区。
它们默认值都可用，但在高并发抓取、对抗恶意响应和多身份隔离场景下需要显式设置。

## 响应资源上限

恶意或异常的服务端可以用超大响应体、超多响应头或极慢的传输拖垮客户端。`ResourceLimits`
覆盖这几种情况：

| 字段 | 含义 |
|---|---|
| `max_response_body_size` | 响应体字节上限，超出即中止 |
| `max_header_count` | 响应头数量上限 |
| `max_header_size` | 单个响应头（名加值）的字节上限 |
| `max_headers_total_size` | 全部响应头合计的字节上限 |
| `max_connections_per_session` | 单个 Session 的物理连接上限，默认不限制 |
| `min_transfer_rate` | 最低传输速率，持续低于该速率即中止（应对 slowloris 类慢速攻击） |

常用的两个快捷方法：

```rust,ignore
let client = Client::builder()
    .preset(preset::chrome_153())
    .with_max_response_body_size(16 * 1024 * 1024)          // 16 MiB
    .with_min_transfer_rate(1024, Duration::from_secs(10))  // 低于 1 KiB/s 持续 10 秒则中止
    .build();
```

需要整体替换时用 `resource_limits(ResourceLimits { .. })`。抓取未知站点时建议至少设置
响应体上限：默认值不会替你判断某个响应是不是异常。

## 请求次数与超时

`AttemptLimits` 可限制一次请求的额外 HTTP 提交和实际建链次数，两个上限默认都不启用。Client、Session、Request 可以逐层继承或收紧；它们不改变 `ResourceLimits`，也不限制整个 Session 的累计请求量。

零额外 HTTP 次数仍允许初次请求和合法重定向；零建链次数仍允许池复用或等待已有共享建链。开启次数上限不会授权重试，也不会隐式增加 timeout。计数规则和配置示例见[请求重发上限与统计](client-session.md#请求重发上限与统计)，总时长与阶段限制见[超时与显式重试](networking/timeouts.md)。

## HSTS

HSTS 决定客户端是否把对某个主机的 `http://` 请求自动升级为 `https://`。三种策略：

| 策略 | 行为 | 适用场景 |
|---|---|---|
| `NoHsts` | 不做任何升级 | 需要精确控制实际发出的 scheme，例如协议行为研究 |
| `StaticHsts::new(hosts)` | 只升级给定的主机列表 | 目标站点固定，希望行为完全可预测 |
| `DynamicHsts::new()` | 依据响应中的 `Strict-Transport-Security` 头动态积累 | 贴近浏览器行为 |

`StaticHsts` 还可以链式调用 `with_preloaded_tlds()`，把 `.dev`、`.app` 这类整体预加载的
顶级域一并纳入。

HSTS 状态属于 Session，不同 Session 之间不共享，这与 Cookie jar 一致。

## TLS 会话恢复与 0-RTT

会话恢复能省掉一次完整握手，但它同时也是一个可被关联的标识：同一张票据被复用，意味着
两次连接可以被服务端关联起来。策略在 Client 上设置：

| `TlsSessionResumptionPolicy` | 行为 |
|---|---|
| `BrowserDefault`（默认） | 每个服务端保留少量票据，优先使用最近收到的那张，贴近浏览器 |
| `Disabled` | 不存储也不提供票据，每次都是完整握手 |
| `Enabled { max_tickets_per_server }` | 显式指定每个服务端的票据容量 |

仅需控制启停或有效期时，可用 `.tls_session_cache_enabled(...)`、`.tls_session_cache_ttl(...)` 和 `.default_tls_session_cache_ttl()`。启停与 TTL 独立，关闭缓存不影响已有连接复用。默认期限、服务端期限和 C ABI 对应入口见[会话缓存](client-session.md#tlsquic-会话缓存)与[C ABI 指南](ffi.md)。

0-RTT（early data）能进一步省掉一个往返，但 early data 可能被重放。是否允许由请求的
幂等性决定，规则与 Chromium 一致：

```text
can_send_early_data = idempotency == IDEMPOTENT
  || (idempotency == DEFAULT && 方法本身是安全方法)
```

因此 `GET`、`HEAD` 默认可以走 0-RTT，而 `POST` 不会，除非显式把请求标记为
`Idempotency::Idempotent`。只有在确认服务端对重复请求免疫时才这样标记。

0-RTT 和早期数据拒绝恢复不依赖 `.retry_on_connection_close(true)`。收到正常早期数据拒绝与已接受请求随后失败是不同情况，后者仍遵守重试授权、body 可重放检查和次数上限。详见[HTTP 协议策略](protocols.md#alt-svc-与-broken-quic)。

## 会话票据分区

浏览器会按顶层站点隔离 TLS 会话缓存，避免第三方通过票据复用做跨站跟踪。
`TlsSessionCachePartitionPolicy` 提供对应的模型：

| 策略 | 缓存键 |
|---|---|
| `Unpartitioned`（默认） | 只按服务端，传统 HTTP 客户端行为 |
| `TopLevelSite` | 加上顶层 schemeful site |
| `TopLevelAndFrameSite` | 顶层与 frame 两级 site |
| `Chromium` | 2.5-key：顶层 site 加上同站/跨站标记 |
| `Firefox` | 顶层 site 加上 `browser_context`（OriginAttributes scope） |

策略在 Client 上选择，具体上下文由 Session 提供：

```rust
use lkrequest::{Client, NetworkPartitionContext, TlsSessionCachePartitionPolicy};

let client = Client::builder()
    .tls_session_cache_partition_policy(TlsSessionCachePartitionPolicy::TopLevelAndFrameSite)
    .build();
let session = client
    .session()
    .network_partition_context(NetworkPartitionContext::new(
        "https://example.com",   // 顶层站点
        "https://widget.test",   // frame 站点
    ))
    .build();
```

这里的 site 字符串应是调用方已经规范化的 schemeful site，不是任意页面 URL；构造函数
不会替你做公共后缀解析。`NetworkPartitionContext::nonce()` 增加临时分区标识，
`.browser_context()` 提供 Firefox OriginAttributes 等不透明上下文。指定分区策略时应
同时提供 Session 上下文；策略名称本身不会创建浏览器标签页或存储隔离环境。

顶层浏览上下文发生变化时应新建 Session，而不是在同一个 Session 上改上下文——这与浏览器
换标签页的语义一致。

## 与其他页面的关系

- 超时（连接、TLS 握手、TTFB、总时长）见[超时与显式重试](networking/timeouts.md)；
- 代理侧的并发与拉黑见 [ProxyPool 轮转与动态生成](advanced/proxy-pool.md)；
- 证书信任与校验开关见[认证与证书](auth-and-certificates.md)。
