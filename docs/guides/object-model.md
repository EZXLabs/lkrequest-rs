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

### 请求生命周期与共享连接

每次 `send()` 或 `send_streaming()` 调用都有独立的执行生命周期。该调用内的重定向、恢复和竞速共享总 deadline 与可选的 `AttemptLimits`；再次调用发送方法会开始新的计数。同一 Session 内的并发请求、不同 Session 的请求都不会共享重发额度。

例如，同一 Session 的请求 A、B 同时访问一个尚未建链的 H2 目标：A 启动连接，B 可以等待并复用它。建链次数记在 A 上；A、B 各自提交的 HTTP 请求记在自己的摘要中。B 取消不会取消 A；A 取消后，B 若接手建链，使用 B 自己的剩余额度和 deadline。

这些行为由库自动管理。Client/Session 上设置的上限是每次操作继承的配置，不是整个对象共用的累计配额；Session 的物理连接并发上限是另一项设置。详见[请求重发上限与统计](client-session.md#请求重发上限与统计)。

流式响应返回 headers 后，请求提交阶段结束，摘要不再随 body 读取变化；body 仍受原总 deadline、读取空闲超时和资源限制约束。保留诊断 observer 不会延长请求的发送权限。

## 下一步

返回[使用场景导航](./)，根据任务进入请求、代理、并发、指纹或诊断示例。

