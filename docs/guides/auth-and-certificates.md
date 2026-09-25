# 认证与证书

本页覆盖两件常被同时用到的事：向目标站点证明身份（请求认证），以及决定信任哪些服务端
证书（CA 与校验）。代理自身的认证属于连接层，见[代理与 DNS](networking.md)。

## 请求认证

`basic_auth` 和 `bearer_auth` 都作用在单个请求上，最终写入 `Authorization` 头：

```rust,ignore
let response = session
    .get("https://api.example.com/private")
    .bearer_auth(&token)
    .send()
    .await?;

let response = session
    .get("https://legacy.example.com/admin")
    .basic_auth("alice", Some("secret"))
    .send()
    .await?;
```

- `basic_auth(user, password)` 的密码是 `Option`：传 `None` 表示空密码，编码结果是
  `user:`，这与只传用户名的 HTTP Basic 语义一致。
- `bearer_auth(token)` 等价于写入 `Bearer <token>`。

需要让**所有**请求都带同一个凭据时，把它放到 `Client` 的默认请求头上，而不是在每个请求
重复：

```rust,ignore
let client = Client::builder()
    .preset(preset::chrome_153())
    .default_header("authorization", format!("Bearer {token}"))
    .build();
```

注意默认请求头会参与 header order，若目标站点对顺序敏感，应确认它出现在浏览器实际会
发送的位置。

## 信任哪些 CA

默认信任内置的 Mozilla root store。三种扩展方式：

| 方法 | 用途 |
|---|---|
| `use_native_certs()` | 在内置根之外，额外加载操作系统的根证书 |
| `add_ca_cert_der(&der)` | 添加单张 DER 编码的 CA 证书 |
| `add_ca_certs_pem(&pem)` | 添加一份 PEM 数据中的全部 CA 证书 |

```rust,ignore
let ca_pem = std::fs::read("corp-root-ca.pem")?;

let client = Client::builder()
    .preset(preset::chrome_153())
    .add_ca_certs_pem(&ca_pem)
    .build();
```

典型场景：

- **企业内网**：流量经过内部 TLS 中间盒，需要加入公司根证书；`use_native_certs()` 通常
  已经足够，因为该证书一般已装进系统信任库。
- **自建服务**：服务端使用自签 CA 签发证书，用 `add_ca_certs_pem` 显式加入。
- **抓包调试**：把抓包工具的根证书加进来，而不是关闭校验。

## 关闭证书校验

`verify(false)` 会跳过**全部**证书校验：

```rust,ignore
let client = Client::builder()
    .preset(preset::chrome_153())
    .verify(false)   // 仅限开发和测试
    .build();
```

这会让连接对中间人完全开放，任何人都能冒充目标站点。它只适用于本地开发和测试环境。
在指纹研究场景下尤其要注意：真实浏览器不会跳过校验，把校验关掉本身就是一种行为差异。
需要信任特定证书时，用上面的 `add_ca_*` 显式添加，不要用 `verify(false)` 一刀切。

## 客户端证书（mTLS）

协议层支持 mTLS，但客户端证书的配置入口需要按当前的 Rust API 与 C ABI 逐一核对，不能
假设默认提供。现状见[功能与协议能力](../reference/capabilities.md)。
