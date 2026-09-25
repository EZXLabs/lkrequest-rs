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

普通响应根据 `content-encoding` 自动解压 `br`、`gzip`、`deflate` 和 `zstd`。`Response::bytes()`/`text()` 返回解压后的内容，但 headers 保留服务端原始值，因此 `content-length` 可能仍表示压缩前的线缆 body 长度，不能用来验证解压后长度。

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
