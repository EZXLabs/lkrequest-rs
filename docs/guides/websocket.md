# WebSocket

WebSocket 从 `Session::websocket()` 发起，使用 Session 的代理及 Client 的 TLS 指纹、CA、
默认 headers 和建链阶段配置。当前实现是 `wss://` 上的 HTTP/1.1 Upgrade，不支持明文
`ws://`、H2 Extended CONNECT 或 H3 WebSocket。它不会自动注入 Session jar 中的 Cookie，
也不会把握手响应的 Set-Cookie 写回 jar。

## 最小示例

```rust,no_run
use lkrequest::{Client, ws::WsMessage};

# async fn example() -> Result<(), lkrequest::error::Error> {
let client = Client::builder().build();
let session = client.session().http1_only().build();

let ws = session.websocket("wss://echo.example.com/socket").connect().await?;

ws.send_text("hello").await?;
match ws.recv().await? {
    WsMessage::Text(text) => println!("收到文本：{text}"),
    WsMessage::Binary(bytes) => println!("收到 {} 字节", bytes.len()),
    other => println!("其他帧：{other:?}"),
}
ws.close(None).await?;
# Ok(())
# }
```

`connect()` 之前可以链式设置握手参数：

| 方法 | 作用 |
|---|---|
| `header(name, value)` | 追加握手请求头，例如鉴权头 |
| `protocol(name)` | 追加 `Sec-WebSocket-Protocol` 子协议 |
| `extension(name)` | 追加 `Sec-WebSocket-Extensions` |

```rust,no_run
# async fn example() -> Result<(), lkrequest::error::Error> {
# let session = lkrequest::Client::builder().build().session().build();
# let token = "access-token";
let mut builder = session
    .websocket("wss://api.example.com/stream")
    .header("authorization", &format!("Bearer {token}"))
    .protocol("json.v2");
if let Some(cookies) = session.cookie_header("https://api.example.com/stream") {
    builder = builder.header("cookie", &cookies);
}
let ws = builder.connect().await?;
# Ok(())
# }
```

取 Cookie 时使用同一主机和路径的 HTTPS URL，使 Secure/path 匹配规则与握手目标一致。
`WsBuilder::new()` 创建的独立 builder 没有 Session，直接 `connect()` 会报错；通常应从
Session 创建。

## 压缩与超时

压缩默认关闭，可在握手前调用
`.extension("permessage-deflate; client_max_window_bits")` 显式协商。服务端接受后，库自动
编码和解码消息，支持 context takeover、分片以及 9 到 15 位客户端压缩窗口；解压后的
单条消息上限为 64 MiB。服务端未接受时保持普通帧，接受了未提供或不支持的参数则握手失败。
`extension()` 不是任意扩展实现的注册接口。

建链继承 DNS/TCP/TLS 阶段配置和 Session 的建链次数上限；HTTP 请求的总超时、TTFB、
read-idle 不会自动覆盖 Upgrade 等待和后续消息收发。异步调用方可用
`tokio::time::timeout` 为 `connect()` 或完整会话设置期限。`recv()` 被取消后不保证保留
半帧解析状态，超时后应结束连接，不能反复取消并重启读取。

## 收发与关闭

连接对象是 `WsConnection`：

- `send_text(&str)`、`send_binary(&[u8])`，或用 `send(WsMessage)` 发送原始帧；
- `recv()` 返回下一条 `WsMessage`，收到 Ping 时会自动回 Pong，但调用方仍可能收到 Ping/Pong 消息；
- `close(None)` 发送正常关闭（状态码 1000），`close(Some((code, reason)))` 指定关闭原因。
  `reason` 连同状态码必须放进一个控制帧，RFC 6455 §5.5 限制整个负载不超过 125 字节；
  超长或使用了端点不允许发送的状态码时，`close()` 会直接返回错误且**不向线路写入任何字节**。

`WsMessage` 有 `Text`、`Binary`、`Ping`、`Pong` 和 `Close` 五种变体。

收发方法接受共享引用。等待 `recv()` 时可并行调用 `send()` 或 `close()`，也可通过 `Arc<WsConnection<_>>` 在任务间共享；同一方向的多次调用按序执行。发送关闭帧后仍可继续等待对端的关闭回复。

底层解析器在接收到部分帧后不保证取消安全。并行发送时应保留正在执行的 `recv()`，不要反复取消并重新开始接收。

## 协议限制

WebSocket 自身使用 H1-only TLS 配置，不会按 Session 的 `http2_only()` 或 `http3_only()`
切换为 H2/H3 握手，也不复用已有 HTTP 请求连接池中的连接。应显式允许目标通过 H1
Upgrade 建链，不能用 Session 的 HTTP 版本选项推断 WebSocket 的线路协议。

同步入口是 `lkrequest::blocking::Session::websocket()`，收发和 `close()` 不带 `.await`；
调用限制见[同步调用](blocking.md)。当前 C ABI 没有 WebSocket handle 或收发接口。

## 与指纹的关系

握手使用 H1 专用 TLS 配置和 Client 默认 headers，不能据此认定其 header 顺序、TLS record
边界和浏览器完全一致。升级后的掩码、分片、压缩协商和 Ping 间隔也需要单独验证，HTTP
preset 的证据不能代替 WebSocket 抓包证据。
