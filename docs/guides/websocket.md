# WebSocket

WebSocket 连接从 `Session` 发起，因此它继承该 Session 的 Cookie jar、代理、TLS 指纹、
超时和 CA 配置。同一个 Session 先用 HTTP 登录、再建立 WebSocket，服务端看到的是同一个
身份。

## 最小示例

```rust,ignore
use lkrequest::ws::WsMessage;

let session = client.session().http1_only().build();

let ws = session.websocket("wss://echo.example.com/socket").connect().await?;

ws.send_text("hello").await?;
match ws.recv().await? {
    WsMessage::Text(text) => println!("收到文本：{text}"),
    WsMessage::Binary(bytes) => println!("收到 {} 字节", bytes.len()),
    other => println!("其他帧：{other:?}"),
}
ws.close(None).await?;
```

`connect()` 之前可以链式设置握手参数：

| 方法 | 作用 |
|---|---|
| `header(name, value)` | 追加握手请求头，例如鉴权头 |
| `protocol(name)` | 追加 `Sec-WebSocket-Protocol` 子协议 |
| `extension(name)` | 追加 `Sec-WebSocket-Extensions` |

```rust,ignore
let ws = session
    .websocket("wss://api.example.com/stream")
    .header("authorization", format!("Bearer {token}"))
    .protocol("json.v2")
    .connect()
    .await?;
```

## 收发与关闭

连接对象是 `WsConnection`：

- `send_text(&str)`、`send_binary(&[u8])`，或用 `send(WsMessage)` 发送原始帧；
- `recv()` 返回下一个数据帧或 close 帧，收到 Ping 时会自动回 Pong，调用方不必处理；
- `close(None)` 发送正常关闭（状态码 1000），`close(Some((code, reason)))` 指定关闭原因。
  `reason` 连同状态码必须放进一个控制帧，RFC 6455 §5.5 限制整个负载不超过 125 字节；
  超长或使用了端点不允许发送的状态码时，`close()` 会直接返回错误且**不向线路写入任何字节**。

`WsMessage` 有 `Text`、`Binary`、`Ping`、`Pong` 和 `Close` 五种变体。

收发方法接受共享引用。等待 `recv()` 时可并行调用 `send()` 或 `close()`，也可通过 `Arc<WsConnection<_>>` 在任务间共享；同一方向的多次调用按序执行。发送关闭帧后仍可继续等待对端的关闭回复。

底层解析器在接收到部分帧后不保证取消安全。并行发送时应保留正在执行的 `recv()`，不要反复取消并重新开始接收。

## 协议限制

WebSocket 走 HTTP/1.1 升级，因此建立连接的 Session 必须允许 H1。示例中显式写了
`http1_only()`；如果 Session 被固定为 `http2_only()` 或 `http3_only()`，握手无法完成。

## 与指纹的关系

握手请求本身带有 Session 的 TLS 指纹和请求头顺序，因此 WebSocket 不会因为切换到升级
路径而失去浏览器一致性。但升级之后的帧内容由应用决定，浏览器在这一层的行为（掩码、
分片大小、Ping 间隔）不在 preset 覆盖范围内，需要自行对照目标站点的真实客户端行为。
