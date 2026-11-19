# 同步调用

没有 async runtime 的程序可使用 `lkrequest::blocking`，无需额外 Cargo feature。
保留一个 Session 来复用 Cookie 和连接；响应的 `text()`、`json()` 等方法与异步版本相同。

```rust,no_run
use lkrequest::{blocking::Client, preset};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder().preset(preset::chrome_157()).try_build()?;
let session = client.session().build();
let (result, summary) = session.get("https://example.com")
    .send_with_attempt_summary();
let response = result?.error_for_status()?;
println!("{}; connections={}", response.status(), summary.connect_initiations());

let mut response = session.get("https://example.com/file").send_streaming()?;
while let Some(chunk) = response.chunk()? {
    println!("{} bytes", chunk.len());
}
# Ok(())
# }
```

`send()`、`chunk()`、WebSocket 收发与 Pool acquire 会阻塞当前线程。
不能在 Tokio async 上下文直接调用这些方法，否则嵌套 `block_on` 会 panic。
异步应用使用异步 API；必须调用已有同步代码时，将完整同步操作放入
`tokio::task::spawn_blocking`。已经开始的阻塞任务不会因丢弃 JoinHandle 自动取消。

## 复用完整 Client 配置

同步 builder 并未转发每一个高级异步 builder 配置。需要自定义 resolver、独立 QUIC TLS
profile 等配置时，先构造普通 Client，再用 `blocking::Client::new(client)` 包装：

```rust
use lkrequest::{blocking, Client, H2DataFramePolicy};

let configured = Client::builder()
    .h2_data_frame_policy(H2DataFramePolicy::BrowserDefault)
    .build();
let client = blocking::Client::new(configured);
let session = client.session().build();
```

流式上传接受 `std::io::Read + Send + 'static`，用法见[流式上传](requests/streaming-upload.md)。
同步流式响应提供 `chunk()`、`bytes()`、`text()`；增量解压的 `chunk_decoded()` 当前仅在
异步 `StreamingResponse` 暴露。连接与总超时仍按配置生效，但正在执行的同步 reader
不能被强制中断。
