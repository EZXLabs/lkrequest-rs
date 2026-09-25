# 理解 Client、Session 与 Request

本章只解释正确使用 API 所需的状态边界。它不是源码架构说明；如果你要修改协议实现或 crate 设计，请阅读[开发者架构与 crate 边界](../development/crate-layout.md)。

## 先按场景选择对象

| 使用场景 | 推荐对象生命周期 |
|---|---|
| 同一账号连续请求 | 共享一个 `Client`，长期复用一个 `Session` |
| 多账号或多租户 | 共享 `Client`，每个账号独立 `Session` |
| 每个任务必须完全隔离 | 共享 `Client`，每个任务创建新 `Session` |
| 有限身份集合并发复用 | 使用 `SessionPool` |
| 只管理代理许可和轮转 | 使用 `ProxyPool` |
| 不使用 async runtime | 使用 `lkrequest::blocking` 包装高层 Client |

## 三个核心对象

```text
Client（共享配置与指纹模板）
  └─ Session（一个虚拟浏览器用户）
       └─ RequestBuilder（一次请求）
            └─ Response / StreamingResponse
```

- `Client` 保存浏览器 preset、默认 headers、超时和资源限制；它不可变、可廉价 clone，通常在整个进程共享。
- `Session` 保存 Cookie、HSTS、Alt-Svc、QUIC fallback、代理配置和连接池；它决定一个虚拟用户的身份边界。
- `RequestBuilder` 保存 method、URL、单次 headers/body 和请求策略；发送完成后不会成为长期身份状态。

## 示例：复用一个登录身份

```rust,ignore
use lkrequest::{preset, Client};

let client = Client::builder()
    .preset(preset::chrome_153())
    .use_native_certs()
    .build();

let session = client.session().build();

let login = session.post("https://example.com/login")
    .form(&[("username", "demo"), ("password", "secret")])
    .send()
    .await?;

let account = session.get("https://example.com/account")
    .send()
    .await?;
```

第二次请求复用同一个 Session，因此可以延续 Cookie、连接和协议发现状态。真实 credential 不应写入源码。

## 示例：隔离两个账号

```rust,ignore
let alice = client.session().build();
let bob = client.session().build();

let alice_response = alice.get("https://example.com/account").send().await?;
let bob_response = bob.get("https://example.com/account").send().await?;
```

两个 Session 不共享 Cookie 或物理连接。不要让互不信任的账号复用同一个 Session，也不要为了并发默认每请求创建 Session；前者会串联身份，后者会失去连接复用和 TLS/QUIC resumption。

## 一次请求会发生什么

从用户视角，一次请求大致经过：

```text
RequestBuilder
  → redirect / retry / middleware
  → DNS 与 direct/proxy 路径
  → H1 / H2 / H3 选择和连接复用
  → response decoding 或 streaming
```

你通常不需要直接操作这些内部阶段。只有当场景涉及协议强制、代理切换、请求重放或性能诊断时，才需要配置相应策略。

## 下一步

返回[使用场景导航](README.md)，根据任务进入请求、代理、并发、指纹或诊断示例。

