# Client、Session 与连接复用

正确划分 Client 和 Session 生命周期，决定了指纹一致性、Cookie 隔离、连接复用和并发上限是否符合预期。

## 何时复用 Client

一个 `Client` 对应一套不可变的共享配置：

- 浏览器 preset 与 TLS/H2/H3 profile；
- 默认 headers 及其顺序；
- DNS resolver、证书信任和 timeout；
- 连接与响应资源限制；
- middleware 和诊断回调。

同一 fingerprint/config 下应复用并 clone Client。切换浏览器版本、TLS profile、DNS 安全边界或全局资源策略时再创建新的 Client。

## 何时新建 Session

Session 表示一个虚拟浏览器用户，拥有：

- Cookie jar；
- H1/H2/H3 连接池；
- 代理和 redirect/retry policy；
- Alt-Svc 与 Broken QUIC 状态；
- HSTS 与网络分区上下文；
- TLS/QUIC session resumption 的使用上下文。

登录身份、代理出口或顶层浏览上下文改变时，应创建新的 Session。不要为了并发请求而每次新建 Session，否则会失去连接复用并放大握手成本。

## 连接复用

- H1 通常一次只承载一个进行中的请求，连接空闲后才能复用。
- H2/H3 在服务端 stream 限制内 multiplex 多个请求。
- `max_connections_per_session()` 是物理连接预算，不是逻辑请求 semaphore。
- `max_pending_h2_requests()` 限制等待远端 stream capacity 的排队请求。
- `pool_stats()` 可读取连接池状态；`pool_clear()` 会关闭并清空当前 Session 的池。

```rust,ignore
let client = Client::builder()
    .preset(preset::chrome_153())
    .max_connections_per_session(4)
    .max_pending_h2_requests(256)
    .build();

let session = client
    .session()
    .idle_timeout(std::time::Duration::from_secs(90))
    .build();
```

## 请求重发上限与统计

`AttemptLimits` 为一次公开请求调用设置可选的额外 HTTP 提交上限和建链启动上限。该调用的协议恢复、连接关闭恢复和应用重试共享计数；同一 Session 的其他请求使用各自的计数。两个上限默认都不启用，原有 retry policy、协议恢复权限和重放安全检查仍决定是否可以重试。

| 配置或计数 | 单位与范围 |
|---|---|
| `extra_http_attempts` | 一次请求中替换已提交请求的额外 HTTP 提交次数 |
| `connect_attempts` | 一次操作中实际启动 TCP/QUIC 连接的次数，包含失败和竞速落败 |
| `max_connections_per_session` | 一个 Session 同时持有的物理连接数 |
| `RetryPolicy` 的 attempt 参数 | 应用重试策略的回调序号，不包含所有协议恢复或建链 |

```rust,no_run
use lkrequest::{AttemptLimits, Client, FixedInterval};
use std::time::Duration;

# async fn example() {
let client = Client::builder()
    .attempt_limits(AttemptLimits::default()
        .with_extra_http_attempts(2)
        .with_connect_attempts(4))
    .build();
let session = client.session()
    .retry_policy(FixedInterval::new(3, Duration::from_millis(200)))
    .build();
let (result, summary) = session.get("https://example.com")
    .send_with_attempt_summary().await;
assert!(summary.extra_http_submissions() <= 2);
assert!(summary.connect_initiations() <= 4);
# }
```

初次 HTTP 提交和每个合法重定向的新一跳不消耗额外次数；替换已经提交过的请求会消耗一次。计数发生在交给协议后端时，不代表服务端已收到完整请求。提交后的错误或取消不会退还次数。若总上限拒绝恢复，会保留原来的响应或错误，不进入这次重试的退避等待。

Client、Session 和 Request builder 均支持 `.attempt_limits(...)`。子级只能继承或收紧父级的有限值；显式放宽会在请求 I/O 前返回配置错误。零表示禁止额外 HTTP 提交；`.without_extra_http_limit()` 清除当前层的覆盖值，子级仍继承父级。可以用 `configured_attempt_limits()` 查看本层值，或用 `effective_attempt_limits()` 查看解析后的上限及来源。

`send_with_attempt_summary()` 和 `send_streaming_with_attempt_summary()` 同时保留原 `Result` 并返回独立摘要，不需要开启原有 diagnostics。需要观察取消时，先调用 `.observe_attempts()` 取得 builder 和 observer，再启动任务；取消后等待任务退出，才能确认最终计数。流式响应发布时 HTTP 统计即固定，之后的 body 读取错误不会被记成新的 HTTP 尝试。

摘要字段与取消观察示例见[请求尝试摘要](advanced/observability.md#请求尝试摘要)。次数上限只约束已经允许的行为；默认关闭的连接关闭重发和 H2-to-H1 回退需分别显式开启，见[超时与显式重试](networking/timeouts.md#retry-configuration)。

### 建链次数上限

同一个 `AttemptLimits` 还支持 `.with_connect_attempts(n)`，与 HTTP 重发上限独立。默认不增加建链总上限；`.without_connect_limit()` 清除本层覆盖并继承父级。零仍允许连接池复用、等待其他请求发起的共享建链，但禁止启动新连接。

计数单位是调用 TCP/QUIC 后端启动一次连接，包括地址切换、代理控制连接、MASQUE 外层连接及内层 QUIC。已启动的失败连接、取消连接和竞速落败连接不退还次数；后端立即拒绝也计一次。本层 DNS、socket/endpoint 准备失败、池查询、加入共享任务及已建立传输上的代理协商不计数。DNS resolver 自身的网络通信不属于这个建链计数。

共享建链由实际启动者计数，等待者使用自己的 deadline 和预算；启动者取消后，重新当选的请求使用自己的额度。`preconnect(url)` 和 WebSocket 建链继承 Client/Session 的有效上限；`preconnect_many` 每个 URL 独立计数。它与 Session 同时存活的物理连接数上限是不同的约束。

有限建链上限会抑制请求触发的可选后台探测，摘要中的 `probe_suppressed_by_connect_limit()` 可见这一结果；服务请求的 TCP/QUIC 竞速仍共享当前额度。`connect_initiations()` 返回已启动次数；摘要的 `effective_limits()` 在执行已开始时返回有效配置，其中 `EffectiveAttemptLimits::connect_scope()` 返回限制来源。

额度拒绝阻止后续建链并保留前一次可用响应或实际错误；没有前一次结果时返回资源限制错误。应用重试和重定向在有限额度下会暂存前一次响应，直到下一轮是否提交 HTTP 已明确，因此可能短暂同时持有两个缓冲响应。建链额度不能代替超时：已经获准的连接或共享任务仍按原 timeout 等待，禁用 timeout 不会由额度隐式增加超时。

## TLS/QUIC 会话缓存

会话缓存默认启用，可通过 Client builder 单独设置有效期或关闭：

```rust
use lkrequest::Client;
use std::time::Duration;

let client = Client::builder()
    .tls_session_cache_enabled(true)
    .tls_session_cache_ttl(Duration::from_secs(7200))
    .build();

let no_cache = Client::builder()
    .tls_session_cache_enabled(false)
    .build();
```

未指定 TTL 时，TLS 1.2 默认一小时，TLS 1.3/QUIC 默认最长七天。指定值可以缩短或延长本地期限，但服务端的更短期限仍生效，TLS 1.3 也不能超过七天。TLS 1.2 的零 lifetime hint 表示未指定期限；TLS 1.3 的零 lifetime 表示立即丢弃。TLS 1.2 续期不会重置原始密钥年龄。

`Duration::ZERO` 表示不缓存。设置 TTL 不会重新启用已关闭的缓存；`.default_tls_session_cache_ttl()` 恢复默认期限，也不改变启停状态。`.tls_session_resumption_policy(...)` 仍可配置每个服务端的容量。重新启用已关闭的缓存时，容量恢复为默认的两个票据。

配置同样适用于网络分区和合成指纹 Session 的独立缓存。关闭缓存后，新建连接进行完整握手；已有连接仍按连接池策略复用，profile 的扩展声明也不因此改变。profile 自身禁用恢复时，启用缓存不会覆盖该设置。

## 并发与背压

大量 task 可以共享一个 Session，但并发能力受以下层级共同限制：

1. Session 物理连接预算；
2. H2/H3 服务端并发 stream 上限；
3. pending request 队列；
4. 应用自身的 task/semaphore；
5. 代理容量和上游限流。

不要把扩大连接数当作绕过服务端 stream 限制的默认方案。连接数会改变握手量、TLS ticket 使用、代理压力和可观察网络行为。

## ProxyPool 与 SessionPool

- `ProxyPool` 只管理代理并发、轮换、健康和 cooldown；获得 `ProxyGuard` 后由调用方决定如何创建/使用 Session。
- `SessionPool` 在 ProxyPool 上复用 Session，并返回自动归还的 `SessionGuard`。
- guard drop 时资源归还池；错误代理可通过 `mark_bad()` 进入 cooldown。
- 需要替换出口身份时使用 `acquire_fresh()`，不要继续复用已标坏 guard 的网络状态。

```rust,ignore
let pool = SessionPool::builder()
    .client(&client)
    .proxies(proxy_configs)
    .max_sessions(32)
    .build();

let session = pool.acquire().await;
let response = session.get("https://example.com").send().await?;
```
