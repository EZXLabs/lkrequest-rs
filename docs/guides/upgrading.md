# 版本升级与迁移

本页只记录**会改变应用行为**的变更，以及升级时需要动手的地方。完整条目见仓库根的
[CHANGELOG](https://github.com/EZXLabs/lkrequest-rs/blob/main/CHANGELOG.md)。

## 从 0.2.5 升级到 0.3.0

0.3.0 重构请求执行与恢复授权，并新增可选的 HTTP 重发和建链总上限。现有请求构造方法继续可用，C ABI 版本仍为 1；Cargo feature 的移除与以下默认行为变化需要检查。

### 自定义 Hickory 配置的类型来源

0.3.0 使用包含分配边界修复的 Hickory 0.26.3 源码。普通 `DnsConfig`
和 C ABI 不变；调用 `HickoryDns::try_with_config`、`with_config` 或
`from_resolver` 的高级 Rust 用户应改从 `lkrequest::dns::hickory` 导入
`config::ResolverConfig`、`config::ResolverOpts`、`TokioResolver` 等类型，
避免与另一个 crates.io 来源的同名类型混用。

### 连接关闭重发与协议回退改为显式开启

连接池连接关闭后的自动重发，以及 H2-to-H1 回退默认关闭。依赖这些行为的应用可显式配置：

```rust
use lkrequest::Client;

let client = Client::builder()
    .retry_on_connection_close(true)
    .h2_fallback_h1(true)
    .build();
```

C 调用方使用 `lk_client_builder_set_retry_on_connection_close` 和
`lk_client_builder_set_fallback_h2_to_h1`。这些开关不会绕过方法幂等性或 body 可重放检查；应用 retry policy 仍独立配置。安全的 HTTP/3 0-RTT 与早期数据拒绝恢复不依赖连接关闭重试开关。

### 新增上限默认不启用

`AttemptLimits` 分别限制额外 HTTP 提交和实际 TCP/QUIC 建链启动次数，同一次请求的重试、重定向和竞速共享预算；同一 Session 的其他请求不共享计数。Client、Session 和 Request 可分层配置，子级只能继承或收紧有限上限。

零额外 HTTP 次数仍允许初次提交和合法重定向；零建链次数仍允许复用连接和等待共享建链。次数上限不能代替 timeout。配置示例、取消观察以及 Rust/C 诊断入口见[请求重发上限与统计](client-session.md#请求重发上限与统计)。

### TLS/QUIC 缓存可以关闭或调整有效期

使用 `.tls_session_cache_enabled(...)`、`.tls_session_cache_ttl(...)` 和
`.default_tls_session_cache_ttl()`，或相应 C setter。TLS 1.2 默认一小时，TLS 1.3/QUIC 最长七天，并遵守更短的服务端期限。关闭缓存不影响已有连接池复用，设置 TTL 也不会重新打开已关闭的缓存。详见[会话缓存](client-session.md#tlsquic-会话缓存)。

### `h2-native` feature 已删除

HTTP/2 始终使用 `lkh2` 引擎。0.3.0 已从 `lkrequest` 和 `lkh2` 删除旧 no-op 别名及转发配置，显式启用它会导致 Cargo 解析失败。直接依赖这两个 crate 的项目，以及再次转发该 feature 的 wrapper crate，都需要移除旧名称：

```toml
# 改前
lkrequest = { git = "...", features = ["h2-native", "quic-h3"] }
# 改后
lkrequest = { git = "...", features = ["quic-h3"] }
```

删掉它不会关闭 HTTP/2，也不需要替换 `lkh2` 依赖；默认构建与 `default-features = false` 均保留 H2。

### Rust 与 C 兼容边界

常用请求 builder 方法和 C ABI 继续保留；这不表示所有 Rust 结构体字面量都无需修改。
`TimeoutConfig` 新增 `read_idle_timeout` 字段，列出全部旧字段的字面量必须补上它，或使用
`..TimeoutConfig::default()`。旧低层 `ConnectionPool` 方法仍保留为 deprecated 包装，
移除计划延后。FFI crate 的内部 Handle/State 结构增加了字段，直接构造这些内部结构的
Rust 代码需调整；C 调用方继续使用 opaque handle。

### 超时默认值与关闭语义

总超时从 60 秒改为 120 秒，并覆盖完整 HTTP 操作，包括重试等待和流式响应读取。
需要保持旧总时长时显式设置 `.total_timeout(Duration::from_secs(60))`。
`None` 现在表示关闭该 deadline，不再替换为有限默认值；`TimeoutConfig::none()`
关闭全部客户端请求期限。新读取空闲超时默认关闭，可以独立限制长连接等待数据的时间：

```rust
use lkrequest::{Client, TimeoutConfig};
use std::time::Duration;

let timeouts = TimeoutConfig {
    total_timeout: Some(Duration::from_secs(60)),
    read_idle_timeout: Some(Duration::from_secs(15)),
    ..TimeoutConfig::default()
};
let client = Client::builder().timeout_config(timeouts).build();
```

C ABI 新增各阶段的 `disable_timeout_*`，已有 setter 的零毫秒仍表示立即超时，不能用来
关闭。完整默认值和同步阻塞边界见[超时指南](networking/timeouts.md)。

### 外部 profile 的加载与导出

完整配置使用 v2 bundle 和 `ClientPreset::from_json_*` / `PresetDocument`，C ABI 使用
`lk_client_builder_set_preset_json` / `lk_preset_export_json`。诊断用的 preset detail JSON
以及旧 `policy_snapshot` 不能直接当作可执行 bundle；已有旧文件需显式迁移 runtime
策略。单独 TLS/H2/QUIC JSON 的范围和覆盖规则见[加载指南](loading-profiles.md)。

## 较早版本迁移

### `ProxyConfig` 与 `HealthCheckConfig` 变成 `#[non_exhaustive]`

这两个结构体现在都不能再用**结构体字面量**构造——`#[non_exhaustive]` 会让 crate 外的字面量无法编译，**连 `..Default::default()` 补全也不行**。

`HealthCheckConfig` 改成从 `Default` 起步再赋值：

```rust,ignore
// 改前（已经不合法）
let health = HealthCheckConfig {
    interval: Duration::from_secs(60),
    timeout: Duration::from_secs(5),
    target_host: "example.com".into(),
    target_port: 443,
};

// 改后
let mut health = HealthCheckConfig::default();
health.interval = Duration::from_secs(60);
health.timeout = Duration::from_secs(5);
health.target_host = "example.com".into();
health.target_port = 443;
```

`ProxyConfig` 的入口是 `ProxyConfig::parse()`（已有 URL）、`ProxyConfig::parse_chain()`（代理链）或新增的 `ProxyConfig::new(scheme)`（已有 `ProxyScheme`），再用链式 setter 叠加：

```rust,ignore
use lkrequest::proxy::{ProxyAuthHeader, ProxyConfig, ProxyScheme};

let proxy = ProxyConfig::new(ProxyScheme::Http {
    host: "proxy.example.com".to_string(),
    port: 443,
})
.with_http_auth("Preshared", "<psk>")?
.with_auth_header(ProxyAuthHeader::Authorization);
```

`ProxyConfig` 刻意没有 `Default`：每种 `ProxyScheme` 都带主机和端口，没有哪个地址能在不凭空发明的前提下充当默认值。**字段仍然是公开可读写的**，封印只针对字面量，已有的 `config.auth = …` 这类赋值照常工作。

两处封印的原因相同：`HealthCheckConfig` 的 MASQUE 字段只在 `masque` feature 下存在，字面量会随最终二进制开了哪些 feature 而需要列出不同的字段集，而下游 crate 控制不了这一点；`ProxyConfig` 则是因为代理认证仍是开放领域（`credential` 与 `auth_header` 本身就是后加的），封印能让下一个字段不至于对每个下游 crate 都构成破坏性变更。

### 升级浏览器 preset

preset 升级是显式的代码改动，不是运行时概念。步骤和验证清单见
[选择浏览器 preset](choosing-a-preset.md)，逐层证据见
[Preset 支持与验证矩阵](../reference/presets.md)。

## 新增能力（不影响现有配置）

### 新的代理类型：MASQUE CONNECT-UDP

新增 `masque://` 代理（RFC 9298 CONNECT-UDP），需要默认关闭的 `masque` feature（蕴含 `quic-h3`）。它只中继 UDP，因此只承载 QUIC/H3；不启用该 feature 时 `masque://` URL 会在 `ProxyConfig::parse()` 阶段就被拒绝并点名 feature，不会解析成一个必然失败的配置。已有的 HTTP CONNECT 与 SOCKS5 行为不变。

用法、三种认证形态与三条已知限制见[代理与 DNS](networking.md)。

### `ProxyCredential`：代理凭据的三种形态

代理认证从“只有用户名/口令”扩展为一个枚举：

| 形态 | 配置方式 | 说明 |
|---|---|---|
| `ProxyCredential::UserPass { username, password }` | URL 里的 `user:pass@`，或 `with_user_pass()` | header 代理编码为 `Basic`，SOCKS5 走 RFC 1929 子协商 |
| `ProxyCredential::Http { scheme, credentials }` | `with_http_auth(scheme, credentials)` | 静态 HTTP auth-scheme（`Preshared`、`PrivateToken`、`Bearer` 等），`credentials` 需已编码；仅 header 代理 |
| `ProxyCredential::Custom(Arc<dyn ProxyAuthenticator>)` | `with_custom_auth()` | 请求时计算凭据；Rust-only，无 C ABI 等价物 |

原有的 `ProxyConfig::auth`（`ProxyAuth { username, password }`）字段**保留且行为不变**，它现在等价于 `UserPass` 的语法糖。`auth` 与 `credential` 同时设置会被 `validate()` 拒绝。

同时新增 `ProxyAuthHeader`，用于选择携带凭据的字段名：默认 `Proxy-Authorization`，可用 `with_auth_header(ProxyAuthHeader::Authorization)` 切到 `Authorization`。SOCKS5 忽略该设置，把 `Http` 或 `Custom` 凭据配到 SOCKS5 代理上会被 `validate()` 报错。

### 健康检查的 MASQUE 探测开关

`HealthCheckConfig` 在 `masque` feature 下多了两个字段：`tunnel_probe`（默认 `false`）与 `masque_outer_config`（默认 `None`）。默认行为对现有配置没有影响——MASQUE 代理会被主动健康检查整体跳过，既不标记健康也不标记失败。细节与安全行为见 [ProxyPool 轮转与动态生成](advanced/proxy-pool.md)。

## 行为变化（无需改代码，但要知道）

### `Cookie` 头的发送顺序

此前 jar 的遍历顺序来自哈希表，同一批 cookie 在不同 Session 中顺序不同。现在按 Chrome
规则排序：path 长的在前，长度相同则先创建的在前。这让顺序变得确定且与浏览器一致，属于
指纹相关的行为改进。如果应用此前用 `cookie_order()` 绕过顺序不确定性，那段配置仍然有效，
但通常已经不再必要。细节见[请求配置的 Cookie 小节](requests/#cookie)。

### 新增的 Cookie 读取 API

`get_cookies_with_attrs(url)` 和 `get_all_cookies()` 返回带完整属性的 `CookieInfo`，
用于同步到浏览器上下文、持久化登录态，以及排查“jar 里有这个 cookie，为什么没带上”。
旧的 `get_cookies` 行为不变。C ABI 对应入口为 `lk_session_get_cookies_with_attrs_json` 和
`lk_session_get_all_cookies_json`，返回由 Session 持有的借用 JSON 字符串，调用方不得释放。
重复查询、修改 Cookie 或释放 Session 会使对应缓冲区失效，绑定需遵守 header 中的生命周期规则。

### ECH 被拒绝时不再降级

服务器不接受 Encrypted ClientHello 时，此前会继续完成握手并返回一个真实域名从未被保护过的
连接。现在会中止，并用服务器提供的 `retry_configs` 重拨一次。**不会**退回到不使用 ECH，
因为那会泄露 ECH 本要隐藏的域名。如果目标站点的 ECH 配置异常，现在会看到明确失败而不是
静默降级。

### Alt-Svc 不再决定 TLS 身份

Alt-Svc 和 HTTPS RR 只决定数据包发往哪里，SNI 与证书校验仍然针对原始 origin。此前使用
广告主机名作为 SNI，会让符合规范的 CDN 部署直接失败。

### `proxy_fallback_direct` 在 MASQUE 路由上不生效

`proxy_fallback_direct` 现在有一个例外：MASQUE 路由**永不**回退直连，无论这个开关是否打开。MASQUE 的用途就是隐藏客户端源地址，隧道失败后静默直连会把用户选它来避免的东西直接泄露给目标。HTTP CONNECT 与 SOCKS5 路由的行为完全不变。

### 非幂等请求的状态码重试

此前错误重试路径检查重放安全性，而状态码重试路径不检查，`POST` 收到 `502` 会被发送两次。
现在非幂等方法只在明确允许的状态策略下才重放。

## 不影响使用的变更

- 依赖升级（rustls 0.23.45 等）没有 API 变化。
- Chrome 146 与 150–153 的 QUIC preset 增加了按 Chromium 规则逐连接生成的 GREASE 与
  Initial 包布局。这是指纹保真度提升，API 不变；影响见[指纹随机化](advanced/randomization.md)。
