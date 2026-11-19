# 响应处理

普通 `send()` 会收集完整响应体；`send_streaming()` 返回可以逐块读取的 `StreamingResponse`。

## 状态与 headers

```rust,ignore
let response = session.get("https://example.com").send().await?;

println!("status={}", response.status());
println!("protocol={}", response.negotiated_version());
println!("final_url={}", response.url());

if response.was_redirected() {
    for hop in response.redirect_history() {
        println!("{} -> {}", hop.status(), hop.redirect_to());
    }
}
```

HTTP 4xx/5xx 本身不会让 `send()` 返回错误。需要状态检查时使用：

```rust,ignore
let response = response.error_for_status()?;
```

## Text、bytes 与 JSON

```rust,ignore
let text: &str = response.text()?;
let owned: String = response.into_text()?;

let bytes: &[u8] = response.bytes();
let owned_bytes = response.into_bytes();

let value: serde_json::Value = response.json()?;
```

消耗型方法会取得 Response 所有权；同一个 Response 不能先 `into_bytes()` 再读取 JSON。

## 自动解压

普通响应根据 `content-encoding` 自动解压 `br`、`gzip`、`deflate` 和 `zstd`。`Response::bytes()`/`text()` 返回解压后的内容，但 headers 保留服务端原始值，因此 `content-length` 可能仍表示解压前的编码 body 长度，不能用来验证解压后长度。

通过 `no_auto_decompress()` 可以请求保留编码后的 body：

```rust,ignore
let response = session
    .get("https://example.com/archive")
    .no_auto_decompress()
    .send()
    .await?;
```

## 流式下载

```rust,ignore
let mut response = session
    .get("https://example.com/large.bin")
    .send_streaming()
    .await?;

while let Some(chunk) = response.chunk().await? {
    consume_raw_chunk(chunk);
}
```

- `chunk()` 返回传输层 body bytes，不执行流式解压。
- `chunk_decoded()` 按 `content-encoding` 增量解压。
- `bytes()`/`text()` 会在 StreamingResponse 上继续读取并收集剩余内容。
- streaming 路径不自动跟随 redirect，也不执行 Session retry；调用方应先检查 status。

压缩响应应从第一次读取起选择 raw 或 decoded 路径，避免先消耗部分压缩数据再开始解码。
`bytes()`/`text()` 收集剩余 body，不会重新包含已经交给调用方的 chunk。响应开始后可能
发生超时、截断或解压错误，拿到 headers 不表示 body 已成功读取。

## 压缩协商

```rust,no_run
use lkrequest::{AcceptEncoding, Client};

# async fn example() -> Result<(), lkrequest::error::Error> {
let session = Client::builder().build().session()
    .default_accept_encoding(AcceptEncoding::GZIP | AcceptEncoding::BR)
    .build();
let response = session.get("https://example.com")
    .accept_encoding(AcceptEncoding::GZIP)
    .send().await?;
# Ok(())
# }
```

支持的位为 `GZIP`、`BR`、`DEFLATE`、`ZSTD`。请求设置优先于 Session 设置，但显式的
`Accept-Encoding` header 优先于这两个生成入口。使用 `.header("accept-encoding", "identity")`
声明不需要内容压缩；`.no_auto_decompress()` 只关闭解码，不会改写协商头，也不能保证
服务端返回未压缩数据。实际解码根据响应的 Content-Encoding 决定。

C ABI 的 `lk_request_set_accept_encoding` 和
`lk_session_builder_set_default_accept_encoding` 接收相同的 bitmask（gzip=1、br=2、
deflate=4、zstd=8）。`lk_request_set_auto_decompress(request, false)` 保留编码后的数据。
C 的 `lk_stream_read` / `lk_stream_read_async` 默认按该开关做增量解压，与 Rust 的 raw
`chunk()` 不同。

`Response::cookies()` 读取当前响应 Set-Cookie 的名值对，完整 Session jar 见
[Cookie 读取接口](./#读取-jar-中的-cookie)。`content_length()` 读取原始 header；
`error_for_status_ref()` 可在不消费 Response 的情况下检查状态。
