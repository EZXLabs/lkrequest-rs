# SessionPool 与 ProxyPool

高并发任务首先要决定“身份是否复用”。吞吐只是结果，Cookie、连接、代理和协议发现状态是否能够跨任务保留才是选型依据。

## 选择哪一种模式

| 模式 | 状态生命周期 | 适用场景 |
|---|---|---|
| 长期 `Session` | 长期复用 Cookie、连接和 Alt-Svc | 单账号、持续访问同一批 origin |
| `SessionPool` | 多个 Session 可借出并自动归还 | 有限身份集合、高并发复用、代理轮换 |
| `ProxyPool` + 新 Session | 只复用代理 permit，每任务创建干净 Session | 任务之间不能共享 Cookie/TLS/连接状态 |

不要用一个 Session 承载多个互不信任账号，也不要为了并发而默认每请求创建 Session。

## SessionPool 示例

```rust,ignore
use std::time::Duration;
use lkrequest::{preset, Client, SessionPool};

let client = Client::builder()
    .preset(preset::chrome_153())
    .use_native_certs()
    .build();

let pool = SessionPool::builder()
    .client(&client)
    .proxies(vec![])
    .max_sessions(32)
    .idle_timeout(Duration::from_secs(120))
    .build();

let session = pool.acquire().await;
let response = session.get("https://example.com").send().await?;
println!("{}", response.status());
// guard drop 后 Session 自动归还。
```

`max_sessions` 限制同时借出的虚拟身份数量。每个 Session 内还可以通过 `max_connections` 限制物理连接；H2/H3 stream 不应被误计为独立物理连接。

## ProxyPool 与全新 Session

当任务之间必须完全隔离时，只从 ProxyPool 获取代理，然后基于共享 Client 创建新 Session：

```rust,ignore
use lkrequest::{Client, ProxyGuard, ProxyPool, Session};

fn fresh_session(client: &Client, guard: &ProxyGuard) -> Session {
    match guard.proxy() {
        Some(proxy) => client.session().proxy_config(proxy.clone()).build(),
        None => client.session().build(),
    }
}

let guard = proxy_pool.acquire().await;
let session = fresh_session(&client, &guard);
```

这种方式不会复用上一个任务的 Cookie 或连接，但会增加 DNS、TCP/TLS/QUIC handshake 成本。

## 容量与失败处理

- 并发任务数、Session 数、代理 permit 和物理连接数应分别设置预算；
- 代理失败时使用 pool 的 cooldown/mark-bad/fresh 机制，不要在多个任务间手写共享下标；
- retry 只重放 replay-safe 请求；代理切换不能自动证明原请求没有到达服务端；
- 多 Session 会把总并发拆到多条连接，可能降低单连接 H2 batching 的收益；
- benchmark 必须记录 Session 数、实际连接数和每连接并发。

固定列表的 `RoundRobin` / `Random`、动态用户名生成、buffer、cooldown、health check 和 `acquire_fresh()` 的完整配置见 [ProxyPool 轮转与动态生成](proxy-pool.md)。

完整示例见公开仓库中的 `lkrequest/examples/session_pool.rs` 和 `lkrequest/examples/proxy_pool.rs`。
