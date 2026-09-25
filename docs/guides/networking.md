# 代理与 DNS

代理和 DNS 决定目标地址在哪里解析、QUIC 是否可用，以及 DNS/ECH/Alt-Svc 信息是否处于同一网络边界。

## 限制地址族与指定拨号目标

Rust 调用方可以限制本进程为 TCP/QUIC 选择的目标地址族。**这是本地连接地址族策略，不是整条代理链路的 IPv4-only 保证。**

```rust,ignore
use lkrequest::{Client, IpFamily};

let client = Client::builder()
    .ip_family(IpFamily::Ipv4)
    .build();
```

`IpFamily::Any` 是默认值；`Ipv4` 和 `Ipv6` 分别严格过滤连接候选地址。
策略作用于最终选定的 system、Hickory 或自定义 resolver，不受 builder 调用顺序影响。
过滤后无候选地址或 IP 字面量不符合策略时返回错误，可通过
`Error::is_address_family_mismatch()` 判断。这类拒绝不会触发代理到直连的回退。
严格模式拒绝 IPv4-mapped IPv6 地址，避免借助地址映射跨越策略。

未配置 `connect_to` 时，`IpFamily::Ipv4` 的具体范围如下：

| 场景 | 行为 |
|---|---|
| 直连目标 | 只连接 IPv4；解析结果仅含 IPv6 时失败 |
| 本机连接代理入口或 SOCKS5 UDP relay | 只允许 IPv4；不符合策略的 relay 地址被拒绝 |
| 普通 `socks5://` 的本地目标解析 | 过滤出 IPv4，再交给代理 |
| HTTP CONNECT、`socks5h://`、MASQUE 的域名目标 | 保留远程解析；代理到目标仍可能使用 IPv6 |
| resolver 自身的 DNS/DoH 查询传输 | 不受此策略控制 |

因此，只设置 `Ipv4` 不能保证目标服务观察到的代理出口一定为 IPv4。
`Ipv6` 也只限制本机负责选址的部分；多跳代理内部的连接和远程解析由对应代理控制。
此 API 不修改操作系统的网卡、路由或 DNS 配置。

### 指定代理连接的目标 IP

需要让代理连接指定 IPv4 时，可以保持请求 URL 为原域名，显式覆盖拨号地址：

```rust,ignore
use lkrequest::{Client, IpFamily};

let client = Client::builder()
    .ip_family(IpFamily::Ipv4)
    .connect_to("example.com", 443, "192.0.2.1:443".parse().unwrap())
    .build();
let session = client.session().proxy("http://127.0.0.1:8080").build();
let response = session.get("https://example.com/").send().await?;
```

示例 IP 是文档保留地址，运行时应换为实际目标地址。
`connect_to` 是可选的固定映射，不会自动解析或刷新目标的 IPv4 地址；调用方负责提供地址并在需要时更新配置。
该例中 HTTP 代理收到 `CONNECT 192.0.2.1:443`，TLS SNI、证书校验和 HTTP Host 仍为 `example.com`。

`connect_to` 按原始 hostname 和端口匹配，
指定目标优先于 Alt-Svc/SVCB 的替代端点。它适用于直连和代理目标，包括 QUIC；
不会替换代理服务器地址。URL、TLS SNI、证书校验名称、HTTP Host/authority、Cookie 作用域和连接池 origin
继续使用原域名。其他 origin 和端口不受影响，重定向也按新 URL 重新匹配。

指定 IPv4 目标可以约束交给代理的目标地址，但不能保证代理供应商的公网出口 IP 固定。
代理场景下 `diagnostics.remote_addr` 是客户端连接到的代理地址，验证公网出口应使用目标服务的回显。

## 支持的代理 URL

```text
http://host:port
http://user:pass@host:port
https://host:port
socks5://host:1080
socks5://user:pass@host:1080
socks5h://user:pass@host:1080
masque://host:443
masque://user:pass@host:443
```

HTTP proxy 配置对 TLS 目标使用 CONNECT 建立 tunnel。parser 也接受 `https://` URL，但当前会归一为同一种 HTTP proxy 配置，并不表示 lkrequest 会先与代理本身建立 TLS。HTTP/HTTPS 默认端口按 URL 语义解析；SOCKS5 未写端口时默认使用 `1080`；`masque://` 未写端口时默认使用 `443`。

`masque://` 需要 `masque` feature（默认关闭）。未启用时 `ProxyConfig::parse()` 会直接返回 `InvalidConfig` 并在消息里点名该 feature，而不是解析出一个必然在首次请求时失败的配置。详见下文 MASQUE 小节。

```rust,ignore
let session = client
    .session()
    .proxy("socks5h://user:pass@proxy.example:1080")
    .build();
```

`SessionBuilder::proxy()` 为了保持 builder 链式接口，在 URL 无效时记录 warning 并忽略配置。需要显式处理配置错误时，先调用 `ProxyConfig::parse()`，再传给 `proxy_config()`。

## socks5 与 socks5h

- `socks5://`：lkrequest 在本地通过 Client resolver 解析目标，再把 IP 交给代理。
- `socks5h://`：目标 hostname 交给 SOCKS5 代理解析，减少本地 A/AAAA 查询泄漏。
- 远程 DNS 不代表所有 DNS 都远程化。HTTPS/SVCB、ECH 或其他 Client resolver 查询仍需按实际配置检查。

## MASQUE CONNECT-UDP 代理

> **实验性功能**：`masque` 默认关闭。MASQUE 专用配置接口和代理互操作行为仍可能调整；目前已通过本地代理测试，尚未完成与独立实现的互操作验证。建议固定经过验证的 commit。

MASQUE 代理（RFC 9298 CONNECT-UDP，承载于 RFC 9297 的 HTTP Datagram）把内层 QUIC 报文装进一条外层 HTTP/3 连接。它是 SOCKS5 UDP ASSOCIATE 的对应物：**只中继 UDP**，目标主机名写在 CONNECT-UDP 请求的 `:path` 里由代理解析，因此这条路由和 `socks5h` 一样属于远程 DNS。

### 前置条件

- 编译时启用 `masque` feature（默认关闭）。它蕴含 `quic-h3`——外层是 HTTP/3、内层是 QUIC，缺一层就没有东西可承载。
- 代理必须支持 HTTP/3 **和** HTTP Datagram，并接受 `connect-udp` 扩展 CONNECT。只提供 H1/H2 形态 CONNECT-UDP 的部署不被支持。

### 配置

```rust,ignore
use lkrequest::proxy::ProxyConfig;

let proxy = ProxyConfig::parse("masque://user:pass@proxy.example.com:443")?;
let session = client.session().proxy_config(proxy).build();
```

`ProxyConfig` 是 `#[non_exhaustive]`，结构体字面量在 crate 外不再编译。入口是 `ProxyConfig::parse()`（已有 URL）或 `ProxyConfig::new(scheme)`（已有 `ProxyScheme`），再用链式 setter 叠加其余配置。

MASQUE **不能作为多跳代理链中的一跳**，也不能自己带链：嵌套隧道会逐层压缩可用 MTU，而内层 MTU 本就受外层 datagram 上限约束。这类配置由 `ProxyConfig::validate()` 直接拒绝。

### 三种认证形态

| 形态 | 配置方式 | 发出的头部值 |
|---|---|---|
| 用户名/口令 | URL 里的 `user:pass@`，或 `with_user_pass()` | `Basic <base64>` |
| 静态 HTTP auth-scheme | `with_http_auth(scheme, credentials)` | `<scheme> <credentials>` |
| 自定义算法 | `with_custom_auth(Arc<dyn ProxyAuthenticator>)` | 由 `authorization_value()` 返回 |

```rust,ignore
use lkrequest::proxy::{ProxyAuthHeader, ProxyConfig};

// Preshared / PrivateToken / Bearer 这类已编码好的凭据：
let proxy = ProxyConfig::parse("masque://proxy.example.com:443")?
    .with_http_auth("Preshared", "<psk>")?
    .with_auth_header(ProxyAuthHeader::Authorization);
```

- `with_http_auth()` 对应 `ProxyCredential::Http { scheme, credentials }`，`credentials` 必须是**已经编码好**的部分，lkrequest 不再做二次编码。`Preshared`、`PrivateToken`、`Bearer` 都走这一形态。
- `with_custom_auth()` 对应 `ProxyCredential::Custom`，用于需要在请求时计算凭据的方案。trait object 无法跨 C ABI，因此这一形态**只有 Rust API 有**。实现 `ProxyAuthenticator` 时注意 `identity_fragment()` 必须能区分同一地址上的不同凭据，否则两个代理会共用同一个冷却/拉黑键。
- URL 只能表达用户名/口令。需要其他 scheme 时先 `parse()`，再调用 `with_http_auth()`。
- `auth` 与 `credential` 同时设置会被 `validate()` 拒绝，避免“生效的到底是哪一个”这种歧义。

### 认证头字段名

这里没有可互操作的统一答案：一部分部署读 `Proxy-Authorization`，masque-go 的文档示例与 RFC 9484 §11 用 `Authorization`，而 RFC 9298 本身完全不规定认证。因此字段名是可选的：

- 默认 `ProxyAuthHeader::ProxyAuthorization`（`Proxy-Authorization`）；
- `with_auth_header(ProxyAuthHeader::Authorization)` 切换为 `Authorization`。

三种凭据形态都走同一个字段名选择，HTTP/3 要求的小写化由内部完成。SOCKS5 没有请求头，所以这个设置对它无效；把 `Http` 或 `Custom` 凭据配到 SOCKS5 代理上会被 `validate()` 报错而不是静默忽略。

### 隧道复用与回收

一个 Session 对一个代理身份（`ProxyConfig::identity()`，含凭据片段）只建立**一条**外层 HTTP/3 连接，访问多个 origin 时在它上面复用多条隧道——这正是 RFC 9298 多路复用的用途。这个复用**止于 Session 边界**：两个 Session 即使配置同一个代理也不会共用外层连接，否则代理就能把用户刻意分开的身份关联起来。

两个回收旋钮：

```rust,ignore
use std::time::Duration;

let client = Client::builder()
    .preset(preset::chrome_153())
    // 一条隧道空载多久后回收；None 表示不按空闲回收
    .masque_tunnel_idle_timeout(Some(Duration::from_secs(30)))
    // 一条外层连接最多挂多少条隧道，超出时先关最久未活动的；0 表示不设上限
    .masque_max_idle_tunnels(512)
    .build();
```

- `masque_tunnel_idle_timeout`：默认 120 秒。`None` 完全关闭按空闲回收，隧道的寿命就等于使用它的内层 QUIC 连接；此时还持有活隧道的外层连接也不会被回收。
- `masque_max_idle_tunnels`：默认 256。这是 `tunnel_idle_timeout: None` 时唯一的增长上限——代理需要为每条隧道保留一个 UDP socket，遍历上千个 origin 的会话否则会把它们全部钉住。
- 两者也可以通过 `ClientBuilder::masque(..)` 一次给全，同一个结构体还携带外层连接的 `bind_addr`、`alpn` 以及证书校验相关的全部字段（`server_name`、`use_native_certs`、`extra_roots`、`verify`），见下一节。`MasqueOuterConfig` 是 `#[non_exhaustive]` 的——从 `Default::default()` 起手再逐字段赋值，字面量（含 `..Default::default()`）在 crate 外不编译。封印的原因是这份配置是 MASQUE 表面还在长的那一端（`verify` 是后加的，FFI 入口、将来的 challenge 认证还要加），而现在封还不需要任何下游付代价。
- 配置挂在 Client 上，连接挂在 Session 上：配置是指纹模板的属性，连接是使用该模板的身份的属性。
- 回收在获取连接时顺带执行，没有后台定时任务。空闲会话的最后几条隧道会在它下次被使用或被 drop 时才退役。

### 代理使用私有 CA 时怎么配

自建或厂商签发的 MASQUE 代理常常挂在私有 CA 后面，操作系统证书库里没有它的签发者。这一节讲的**全都是到代理那一跳**（外层 HTTP/3 连接）的证书校验，和目标站点那一跳完全分开——`add_ca_cert_der()` / `add_ca_certs_pem()` / `use_native_certs()` / `verify()` 配的是目标站点，`masque_` 前缀的这一组配的是代理。两者**互不影响**，这是刻意的：为调试一跳放宽的信任不应悄悄成为另一跳的信任锚。所以同一个私有 CA 如果两跳都要用，就得给两跳各配一次。

```rust,ignore
use lkrequest::Client;

let pem = std::fs::read("proxy-ca.pem")?;

let client = Client::builder()
    .preset(preset::chrome_153())
    // 私有 CA 代理不需要系统证书库里的任何东西
    .masque_use_native_certs(false)
    // PEM 入口：解析失败（格式坏、里面一张证书都没有）返回错误
    .masque_add_ca_certs_pem(&pem)?
    // 证书上写的是主机名，但代理是按 IP 访问的
    .masque_server_name("proxy.internal")
    .build();
```

**`extra_roots`：追加信任锚，PEM 与 DER 两种入口。** 字段本身是 DER（`Vec<CertificateDer<'static>>`），而 CA 一般以 `.pem` 文件的形态发到手上，所以两个入口都有：

| 入口 | 形态 | 解析失败时 |
|---|---|---|
| `ClientBuilder::masque_add_ca_certs_pem(&[u8])` | PEM bundle（可含多张证书） | 返回 `Err(Error::InvalidConfig)`，且**什么都不追加** |
| `MasqueOuterConfig::add_ca_certs_pem(&[u8])` | 同上，返回追加了几张 | 同上 |
| `ClientBuilder::masque_add_ca_cert_der(&[u8])` | 单张 DER | 首次用该代理发请求时报 `InvalidConfig` |
| `MasqueOuterConfig::extra_roots` | 直接给 DER 向量 | 同上 |

PEM 入口会跳过非证书段（同一个文件里的私钥不算错误），但**一张证书都没解析出来算错误**——路径打错、误把 DER 喂进 PEM 入口这类情况如果被静默忽略，结果就是代理被拿着谁都没打算用的信任锚去校验。DER 入口不在调用点解析，坏字节会在构造外层连接时报错。

**`use_native_certs`：默认 `true`，私有 CA 场景建议关掉。** 留着它意味着系统证书库里**任何**一个公共 CA 都能为“在代理地址上应答的东西”背书；关掉它，外层连接就只认 `extra_roots` 里那几张。代价是代理换成公共证书时要记得改回来。代理是公共 CA 签发的（多数商业 MASQUE 服务）就保持默认，什么都不用配。

**`server_name`：默认用代理 URL 里的主机名，按需覆盖。** 它同时决定 SNI 和证书校验用的名字。需要覆盖的情形只有一种：代理证书上写的名字和你访问它用的名字不一致——最常见的是按 IP 访问（`masque://10.0.0.10:443`，而证书上是 `proxy.internal`），其次是证书只签了内部域名。名字对不上时是校验失败，不是连接失败，错误里会指出这一点。

**`verify: false`：只用于开发与测试。** 默认 `true`。设成 `false` 会跳过外层连接的**全部**证书校验——链、签发者、名字都不看：

```rust,ignore
// 开发环境：代理证书还没签好，先让隧道跑起来
let client = Client::builder()
    .preset(preset::chrome_153())
    .masque_verify(false) // 不安全，仅限开发与测试
    .build();
```

这条连接由此**对中间人完全开放**，而这里的代价比目标站点那一跳的 `verify(false)` 更值得说清。任何能在代理地址上应答、或能挤到代理前面的东西，都会成为外层 TLS 的终端，于是它拿到的正是代理本该拿到的东西：这条连接上**所有**隧道的 CONNECT-UDP 目标，加上会话全部行为的流量模式（内层 QUIC 是作为 UDP 负载装在外层里的）。内层 QUIC 自己的加密仍在，内层证书也照常按目标站点那一跳的配置校验，所以内层内容读不到；但“把访问了哪些站点这件事收进一条加密隧道”本来就是配 MASQUE 的目的之一，而它没了——并且此时你连对面是不是你选的那个代理都无法确认。

`verify: false` 时 `use_native_certs` 与 `extra_roots` 完全不被读取，“没有任何信任锚”那条报错也不适用——没有信任锚可言。日志里会留一条 `masque.outer_certificate_verification_disabled` 警告。

健康检查探测用的信任锚就是这一份配置，见 [ProxyPool 轮转与动态生成](advanced/proxy-pool.md#masque-代理的探测tunnel_probe-与-masque_outer_config)。

**C 侧（FFI）怎么配。** 同一套配置在 C ABI 上是一个不透明句柄 `lk_masque_config_t`：

```c
lk_masque_config_t *outer = NULL;
lk_masque_config_new(&outer);

/* 私有 CA 代理不需要系统证书库里的任何东西 */
lk_masque_config_set_use_native_certs(outer, false);
/* PEM 入口，收的是文件内容而不是路径；坏 bundle 会返回 LK_ERR */
size_t added = 0;
lk_masque_config_add_ca_certs_pem(outer, pem_bytes, pem_len, &added);
/* 证书上写的是主机名，但代理是按 IP 访问的 */
lk_masque_config_set_server_name(outer, "proxy.internal", 14);

/* 请求路径 */
lk_client_builder_set_masque_config(builder, outer);
/* 健康检查的 CONNECT-UDP 探测——修 C 侧假阴性的关键一步 */
lk_proxy_pool_builder_set_masque_tunnel_probe(pool_builder, outer);

/* 两个挂载入口都是拷贝，所以句柄自己释放一次就好 */
lk_masque_config_free(outer);
```

隧道回收的两个旋钮也在这个句柄上：`lk_masque_config_set_tunnel_idle_timeout(outer, ms)`（`0` 表示不按空闲回收）与 `lk_masque_config_set_max_idle_tunnels(outer, n)`（`0` 表示不设上限）。

`verify` 同样有 C 入口：`lk_masque_config_set_verify(outer, false)`。**它是最后手段，不是私有 CA 的解法**——上面那个例子（加信任锚、关掉系统证书库、必要时覆盖证书名字）才是，它保留了认证。`set_verify(false)` 留给证书根本无法校验的情况，比如证书上写的名字在这套环境里不解析。之所以要给 C 入口：假阴性不分语言，C 侧调用方如果没有这个开关，就只剩"健康代理被拉黑"而无路可走，而 Rust 侧有 `masque_verify(false)`。风险与 Rust 侧完全相同，见上面 `verify` 那一段。它和 `lk_client_builder_set_verify`（目标站点那一跳）互不影响。

### 已知限制

**DNS 自动发现的 ECH config 与 H3 提示不可用。** MASQUE 路由是远程 DNS 路由，客户端不对目标做本地 HTTPS/SVCB 查询——那会把目标主机名从代理之外的通道泄露出去，和 `socks5h` 同因。后果是：HTTPS record 里的 ECHConfigList 不会被自动采用，记录里的 H3 线索也用不上（MASQUE 路由本来就不需要它，见下）。**显式配置的 ECH 仍然生效**：`ClientBuilder::ech_config()` 与 `SessionBuilder::ech_config()` 的覆盖在这条路由上照常发出。

**外层连接不是浏览器指纹。** 到代理的那一跳使用 quinn 自带 rustls 的默认配置（TLS 1.3、ALPN `h3`），不套用任何浏览器 profile：代理不是被模仿的站点，对它伪装没有收益。因此不应假设这条连接在路径上与浏览器流量不可区分——我们只保证它不套用 profile，没有实测过它的可识别程度。**目标站点看到的内层指纹不受影响**——隧道对内层 QUIC 栈表现为一个普通 UDP socket，内层连接不知道自己在隧道里，每个字节仍由浏览器 profile 决定。

**只承载 QUIC。** 配置了 MASQUE 代理时：

- H1/H2 请求（包括 `http1_only()`、`http2_only()` 和 `http://` 明文目标）会以明确的代理协议错误失败，消息说明该代理只中继 UDP、H1/H2 需要 HTTP CONNECT 或 SOCKS5 代理。**不会静默直连**。
- 隧道建立失败也不回退直连，**即便开启了 `proxy_fallback_direct`**。MASQUE 存在的目的就是隐藏客户端源地址，静默直连会把用户选它来避免的东西直接泄露给目标。一个看得见的失败严格优于一次让人去匿名化的成功。
- 隧道建立失败同样不回退 H2，错误原样返回给调用方。隧道建立之后才发生的内层 QUIC 握手失败会按常规 fallback 策略尝试转向 TCP，而那次尝试会立刻撞上同一个“只中继 UDP”的错误——结果仍然安全（不会直连），但最终错误消息会盖住内层握手的真实原因，详见[故障排查](troubleshooting.md)。
- 反过来，这条路由上 H3 不是“发现后才启用的升级”，而是唯一的传输方式，因此不等待 Alt-Svc 广告就直接尝试——那条广告在这里永远不会到达，因为它需要先有一个 H2 响应。

隧道失败的判读见[故障排查](troubleshooting.md)；健康检查探测见 [ProxyPool 轮转与动态生成](advanced/proxy-pool.md)。

## 多跳代理

```rust,ignore
use lkrequest::proxy::ProxyConfig;

let chain = ProxyConfig::parse_chain([
    "socks5://hop1.example:1080",
    "socks5h://hop2.example:1080",
])?;

let session = client.session().proxy_config(chain).build();
```

数组顺序是客户端到目标方向。每一跳都必须成功建立下一跳 tunnel；错误信息会标记 proxy chain hop。

## DNS resolver

默认 `DnsConfig::System` 使用操作系统 resolver。同一进程中并发的相同 `(host, port)` 查询会 singleflight 合并，但完成结果默认不做正向缓存。

```rust,ignore
use lkrequest::{DnsConfig, SystemDnsCacheConfig};
use std::time::Duration;

let client = Client::builder()
    .preset(preset::chrome_153())
    .dns(DnsConfig::System)
    .system_dns_cache(
        SystemDnsCacheConfig::positive(Duration::from_secs(30))
            .with_max_entries(1024),
    )
    .build();
```

`DnsConfig::Google`、`Cloudflare`、`Quad9` 和 `Custom` 使用 Hickory resolver。对应的 `*Https` 变体需要 `doh` feature。

## 多地址与 IPv6

resolver 可以返回多个 IPv4/IPv6 地址。连接建立会在资源预算内尝试候选地址；不要假设第一个 DNS 结果就是最终连接地址。代理 hostname 也会经过相同的解析与拨号过程。

## HTTPS/SVCB、ECH 与 H3

支持 HTTPS record 的 resolver 可以提供 ALPN、替代端口、ECHConfigList 和 H3 线索。需要注意：

- 系统 resolver 当前不查询 HTTPS record；
- `ipv4hint`/`ipv6hint` 会被解析和暴露，但内部连接不会直接使用 hint 拨号；
- 远程 DNS 路由（`socks5h`、HTTP CONNECT、`masque`）上不做本地 HTTPS record 查询：那会把目标主机名从代理之外的通道泄露出去。因此这些路由上 DNS 自动发现的 ECH 与 H3 线索都不可用，显式配置的 ECH 仍然生效；
- ECH、目标 A/AAAA 和代理出口不在同一 DNS 视图时，可能获得不可用配置；
- QUIC 经 SOCKS5 需要代理支持 UDP ASSOCIATE/relay，并启用 `quic-h3`；
- QUIC 经 MASQUE 需要代理支持 H3 与 HTTP Datagram，并启用 `masque`。
