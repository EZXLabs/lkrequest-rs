# 请求体

`RequestBuilder` 接受内存中的 bytes、文本、JSON、URL-encoded form 和 multipart，也支持 `body_reader(reader, length)` 与 `body_stream(stream, length)` 增量上传。大文件可直接使用异步 reader；同步 Rust API 提供接收 `std::io::Read` 的 `body_reader()`。具体示例与长度约束见[流式上传](streaming-upload.md)。

## Bytes 与文本

```rust,ignore
let response = session
    .post("https://example.com/data")
    .header("content-type", "application/octet-stream")
    .body(vec![0x01, 0x02, 0x03])
    .send()
    .await?;

let response = session
    .post("https://example.com/message")
    .text_body("hello")
    .send()
    .await?;
```

`body()` 和 `text_body()` 不替你选择业务 `Content-Type`，需要时应显式设置。

## JSON

`json()` 使用 Serde 序列化，并设置 `application/json`：

```rust,ignore
#[derive(serde::Serialize)]
struct CreateTask<'a> {
    title: &'a str,
    priority: u8,
}

let response = session
    .post("https://example.com/tasks")
    .json(&CreateTask { title: "docs", priority: 1 })
    .send()
    .await?;
```

序列化失败不会 panic；错误会延迟到 `send()` 返回。

## URL-encoded form

```rust,ignore
let response = session
    .post("https://example.com/login")
    .form(&[("username", "alice"), ("password", "secret")])
    .send()
    .await?;
```

该方法设置 `application/x-www-form-urlencoded`。

## Multipart

```rust,ignore
use lkrequest::multipart::Multipart;

let form = Multipart::new()
    .text("description", "profile image")
    .file("upload", "avatar.png", "image/png", image_bytes);

let response = session
    .post("https://example.com/upload")
    .multipart(form)
    .send()
    .await?;
```

multipart 会自动生成 boundary 和 `Content-Type`。字段名、文件名或 MIME type 中含 CR/LF 时，请求会被拒绝以防止 part header 注入。

## 内存与重放边界

- `body()`、JSON、form 和 multipart 仍缓存在内存中，可以被 redirect/retry 流程重建。
- 流式请求体不会完整缓存；传输层领取来源后，禁止自动重放，包括保留请求体的重定向。需要重试时，应重新创建来源。
- 是否允许自动重放仍由 method、`Idempotency` 和具体错误阶段共同决定。
- 对不可重复操作，应设置 `Idempotency::NotIdempotent`，并在应用层处理不确定结果。
- 上传体量应同时受应用自身限制；`ResourceLimits` 主要约束响应与连接资源，不等同于上传配额。
