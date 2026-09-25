# 版本升级与迁移

本页只记录**会改变应用行为**的变更，以及升级时需要动手的地方。完整条目见仓库根的
[CHANGELOG](https://github.com/EZXLabs/lkrequest-rs/blob/main/CHANGELOG.md)。

## 需要动手改的

### `h2-native` feature 已弃用

HTTP/2 始终使用 `lkh2` 引擎，`h2-native` 在 0.2.x 中只是一个 no-op 兼容别名，**0.3.0
会从 `lkrequest` 和 `lkh2` 中彻底删除**。显式写了这个 feature 的应用现在就应该移除：

```toml
# 改前
lkrequest = { git = "...", features = ["h2-native", "quic-h3"] }
# 改后
lkrequest = { git = "...", features = ["quic-h3"] }
```

删掉它不会改变任何行为。

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
但通常已经不再必要。细节见[请求配置的 Cookie 小节](requests/README.md#cookie)。

### 新增的 Cookie 读取 API

`get_cookies_with_attrs(url)` 和 `get_all_cookies()` 返回带完整属性的 `CookieInfo`，
用于同步到浏览器上下文、持久化登录态，以及排查“jar 里有这个 cookie，为什么没带上”。
旧的 `get_cookies` 行为不变。这两个方法目前**尚未导出到 C ABI**。

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
