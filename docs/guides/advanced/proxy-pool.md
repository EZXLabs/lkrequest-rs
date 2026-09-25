# ProxyPool 轮转与动态生成

`ProxyPool` 将代理选择、并发许可和失败状态从业务请求中分离。它适合“每个任务使用一个代理，但不一定复用 Session”的场景；如果还要复用 Cookie、连接和协议发现状态，应使用 `SessionPool`。

## 选择代理来源

| 来源 | Builder API | 适用场景 | 轮转与健康状态 |
|---|---|---|---|
| 固定列表 | `.proxies(...)` | 自有节点、数量稳定 | 支持 `RoundRobin` / `Random`、cooldown 和主动健康检查 |
| 动态生成 | `.proxy_fn(...)` | 住宅代理网关、用户名携带 session ID | 每次生成临时身份；`.rotation()` 与静态 cooldown 不适用 |
| 自定义 provider | `.proxy_provider(...)` | 主备、分组、租约或外部服务 | 行为由 `ProxyProvider` 实现决定 |

`max_proxies` 限制同时持有的代理许可数量，不代表代理列表长度，也不等于 HTTP 连接数。

## 固定列表轮转

```rust,ignore
use lkrequest::proxy::{ProxyConfig, RotationStrategy};
use lkrequest::ProxyPool;

let proxies = [
    "http://user:pass@proxy-a.example.com:8080",
    "socks5h://user:pass@proxy-b.example.com:1080",
]
.into_iter()
.map(ProxyConfig::parse)
.collect::<Result<Vec<_>, _>>()?;

let pool = ProxyPool::builder()
    .proxies(proxies)
    .rotation(RotationStrategy::RoundRobin)
    .max_proxies(16)
    .build();

let guard = pool.acquire().await;
let session = match guard.proxy() {
    Some(proxy) => client.session().proxy_config(proxy.clone()).build(),
    None => client.session().build(),
};
```

`RoundRobin` 按顺序循环分配；`Random` 从当前可用静态代理中随机选择。业务代码应持有 `ProxyGuard` 直到该代理对应的任务结束，guard drop 后许可自动归还。

## 动态生成代理

住宅代理服务通常通过用户名中的 session ID 生成新出口。此时可用闭包按需生成配置，并用 buffer 提前解析：

```rust,ignore
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use lkrequest::ProxyPool;

let sequence = Arc::new(AtomicU64::new(1));
let pool = ProxyPool::builder()
    .proxy_fn(move || {
        let id = sequence.fetch_add(1, Ordering::Relaxed);
        format!(
            "http://user-session-{id:08}:pass@residential.example.com:7777"
        )
    })
    .proxy_buffer(32)
    .max_proxies(16)
    .build();
```

动态 provider 的每个结果都是临时代理身份，因此：

- `.rotation(...)` 不控制动态结果的顺序；
- `ProxyGuard::mark_bad()` 和静态代理 cooldown 不会永久拉黑整个网关；
- 失败后的正确动作通常是丢弃当前身份并调用 `acquire_fresh()`；
- 如果供应商要求归还租约、上报质量或控制地区，应实现自定义 `ProxyProvider`。

## 失败后重新获取代理

```rust,ignore
let mut guard = pool.acquire().await;

for attempt in 0..3 {
    let session = match guard.proxy() {
        Some(proxy) => client.session().proxy_config(proxy.clone()).build(),
        None => client.session().build(),
    };

    match session.get("https://example.com/").send().await {
        Ok(response) if response.status().is_success() => break,
        Ok(_) | Err(_) if attempt < 2 => {
            guard = pool.acquire_fresh(&guard).await;
        }
        _ => break,
    }
}
```

`acquire_fresh()` 会先标记旧 guard，再在旧 guard 仍持有 permit 时执行下一次 acquire。它需要池中存在空闲 permit；当 `max_proxies = 1` 或所有并发任务同时切换时可能等待。饱和场景应显式执行 `guard.mark_bad()`、drop 旧 guard，再调用 `pool.acquire()`。新 acquire 是新的选择过程，但静态随机策略不保证一定返回不同地址。

代理切换不等于请求可安全重放。对于 POST、上传和带副作用的接口，必须先确认服务端是否可能已经收到请求，再决定是否 retry。

## 静态代理 cooldown 与健康检查

```rust,ignore
use std::time::Duration;
use lkrequest::{BadProxyConfig, HealthCheckConfig, ProxyPool};

// `HealthCheckConfig` 是 `#[non_exhaustive]`：结构体字面量在 crate 外不再合法，
// 连 `..Default::default()` 补全也不行。从 Default 起步再逐个赋值。
let mut health_check = HealthCheckConfig::default();
health_check.interval = Duration::from_secs(60);
health_check.timeout = Duration::from_secs(5);
health_check.target_host = "example.com".into();
health_check.target_port = 443;

let pool = ProxyPool::builder()
    .proxies(proxies)
    .bad_proxy_config(BadProxyConfig {
        failure_threshold: 3,
        window: Duration::from_secs(60),
        cooldown_duration: Duration::from_secs(300),
        max_cooldowns: 5,
    })
    .health_check(health_check)
    .build();
```

封印 `HealthCheckConfig` 的原因是它的 MASQUE 字段只在 `masque` feature 下存在：字面量会随最终二进制开了哪些 feature 而需要列出不同的字段集，而下游 crate 控制不了这一点。`BadProxyConfig` 不受影响，字面量照常可用。

`mark_bad()` 是业务失败信号，主动 health check 是网络可达性信号；二者都不能单独证明某个代理适合特定站点。目标站点封禁、地区不符和账号风控仍需业务层分类。

### 健康检查只应用于静态代理列表

health check 只对**静态** provider（固定代理列表）生效。动态 provider（闭包）的代理身份是一次性的，会被跳过。

### MASQUE 代理的探测：`tunnel_probe` 与 `masque_outer_config`

默认的 health check 是“能不能通过这个代理建立一条 TCP 连接”。对 MASQUE 代理来说这个结论是**错的**：CONNECT-UDP 跑在外层 HTTP/3 连接上，TCP 端口可达完全不能说明代理支持 HTTP Datagram、接受 `connect-udp`、或认可这套凭据。因此 MASQUE 代理走单独的判定：

```rust,ignore
use lkrequest::HealthCheckConfig;

let mut health_check = HealthCheckConfig::default();
health_check.tunnel_probe = true;
// 必须同时给出外层连接的构造方式，通常直接复用请求本身用的那一套
health_check.masque_outer_config = Some(client.masque_config().clone());
```

| `tunnel_probe` | `masque_outer_config` | 行为 |
|---|---|---|
| `false`（默认） | 任意 | MASQUE 代理被主动检查**整体跳过**：既不标记健康，也不标记失败，永远不会被 health check 拉黑。坏代理靠 `ProxyPool::mark_bad_proxy()` 的被动路径发现 |
| `true` | `None` | **同样跳过**，并打一条 `warn`。这是刻意的安全行为，见下 |
| `true` | `Some(..)` | 真正探测：建立外层 HTTP/3 连接、对 `target_host:target_port` 开一条 CONNECT-UDP 隧道、确认它就绪（2xx，且不违反 RFC 9297 §3.2 对 Capsule Protocol 响应的要求），随后立刻关闭。成功可把代理从 cooldown 中解救出来，失败或超时按普通失败计入坏代理计数 |

**为什么“开了探测但没给 outer config”是跳过而不是拉黑**：信任锚不是连接池可以猜的东西。自建或厂商签发的 MASQUE 代理常常挂在私有 CA 后面，它完全健康，但拿操作系统证书库去校验会握手失败并计入坏代理计数——这是**假阴性**，health check 会主动拉黑能用的代理，比不检查严格更糟。所以这里没有默认值：什么都不说总是可以补救的，把健康代理拉黑不是。

**探测用的信任锚就来自这份 `MasqueOuterConfig`**，和请求本身用的是同一个结构体——上面那行 `client.masque_config().clone()` 正是把请求那一套原样交给探测。这也正是上一段那条规则的成因：没有这份配置，探测就没有任何信任锚可用，于是只能跳过而不是拿系统证书库去猜。私有 CA 的两个入口（PEM 与 DER）、`use_native_certs` 的取舍、`server_name` 何时需要覆盖、以及 `verify: false` 的风险，都在[代理与 DNS 的“代理使用私有 CA 时怎么配”](../networking.md#代理使用私有-ca-时怎么配)一节。

探测与请求共用配置也意味着：探测的严格程度和请求一致。`verify: false` 会一并放宽探测（它于是不再能区分“真的是那个代理”和“有东西在那个地址上应答”），`verify: true` 但信任锚配错则会让一个健康的代理被探测判为失败——探测失败按普通失败计入坏代理计数，所以配错信任锚的代价是把能用的代理推进冷却，这也是这两处文档要相互指路的原因。

其余要点：

- 探测每轮对每个代理要付一次完整 QUIC 握手，这是它默认关闭的另一个原因。
- `timeout` 会端到端地约束这次探测：DNS、外层 QUIC/HTTP-3 握手和 CONNECT-UDP 交换合在一起算。`target_host` / `target_port` 就是代理被要求开隧道去的目标。
- `masque_outer_config` 里真正起作用的是 `bind_addr`、`server_name`、`alpn`、`verify` 和信任锚；隧道生命周期旋钮（`tunnel_idle_timeout`、`max_idle_tunnels`）对一个开完立刻关掉的探测没有意义，会被忽略。
- 这两个字段都需要 `masque` feature。没有它就没有 CONNECT-UDP 客户端，字段不存在，MASQUE 代理无条件被跳过（也不会因此被归责）。
- 非 MASQUE 代理完全不受这两个设置影响。
- `HealthCheckConfig` 与 `MasqueOuterConfig` 都是 `#[non_exhaustive]`，两者都从 `Default::default()` 起手逐字段赋值，字面量（含 `..Default::default()`）在 crate 外不编译。

C 侧走 `lk_proxy_pool_builder_set_masque_tunnel_probe(pool_builder, outer)`（`SessionPool` 同名对应入口），`outer` 是 `lk_masque_config_t` 句柄，通常和请求路径 `lk_client_builder_set_masque_config` 用的是同一个。它一次把 `tunnel_probe` 和 `masque_outer_config` 都给全，所以 C 侧不会出现“开了探测但没给信任锚”这个中间状态。它和 `lk_proxy_pool_builder_set_health_check` 的调用顺序无关（两者在 build 时合并），但 health check 本身必须配上——只设探测不设 health check 会让 `lk_proxy_pool_builder_build` 返回 `LK_ERR_INVALID_CONFIG`，而不是建出一个永远不探测的池。句柄的全部入口见[代理与 DNS 的“代理使用私有 CA 时怎么配”](../networking.md#代理使用私有-ca-时怎么配)。

MASQUE 代理本身的配置与限制见[代理与 DNS](../networking.md)，失败判读见[故障排查](../troubleshooting.md)。

## ProxyPool 与 SessionPool

| 需求 | 推荐方式 |
|---|---|
| 每任务全新 Cookie 和连接状态 | `ProxyPool` + `client.session().build()` |
| 多个长期身份并发复用 | `SessionPool` |
| 失败后重新选择代理并创建新身份 | `ProxyPool::acquire_fresh()` 或 mark/drop/acquire |
| 失败后重新选择池化 Session | `SessionPool::acquire_fresh()` |

完整可运行流程见 `lkrequest/examples/proxy_pool.rs`、`proxy_dynamic.rs`、`proxy_dyn_fallback.rs` 和 `session_pool.rs`。示例中的地址和 credential 必须保持为 placeholder。
