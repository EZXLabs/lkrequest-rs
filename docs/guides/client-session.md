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
