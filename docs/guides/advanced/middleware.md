# Middleware

Middleware 在请求发出前和响应返回后各插入一个钩子，适合统一注入审计日志、改写请求、
检查响应，或在请求真正发出前直接中止它。

## 实现一个 middleware

`Middleware` trait 有三个方法，都带默认实现，只实现需要的那个即可：

```rust,ignore
use lkrequest::middleware::{Middleware, MiddlewareRequest, MiddlewareResponse};
use lkrequest::error::Result;

struct RequestId;

impl Middleware for RequestId {
    fn on_request(&self, mut req: MiddlewareRequest) -> Result<MiddlewareRequest> {
        let id = uuid();
        req.headers.insert("x-request-id", id.parse().unwrap());
        tracing::debug!(method = %req.method, url = %req.url, "发出请求");
        Ok(req)
    }

    fn on_response(&self, resp: MiddlewareResponse) -> Result<MiddlewareResponse> {
        tracing::debug!(status = %resp.status, bytes = resp.body.len(), "收到响应");
        Ok(resp)
    }

    fn name(&self) -> &str {
        "request-id"
    }
}
```

实现类型必须是 `Send + Sync`，因为同一个实例会被并发请求共享。`name()` 默认返回类型名，
用于 tracing 和调试输出。

可读写的字段：

| 类型 | 字段 |
|---|---|
| `MiddlewareRequest` | `method`、`url`、`headers`、`body: Option<Bytes>` |
| `MiddlewareResponse` | `status`、`headers`、`body: Bytes`（已解压） |

流式上传在 `on_request` 中的 `body` 是 `None`，框架不会为了给 middleware 看一眼就把流
读出来。给它赋一个 `Some(bytes)` 会把流式上传替换成缓冲上传，这通常不是你想要的。

## 注册位置

Client 和 Session 都能挂 middleware，两处都会执行：

```rust,ignore
let client = Client::builder()
    .preset(preset::chrome_153())
    .middleware(RequestId)          // 所有 Session 共享
    .build();

let session = client.session()
    .middleware(TenantHeader::new("acme"))   // 只作用于该 Session
    .build();
```

把跨身份、跨任务都成立的逻辑放在 Client；把与某个身份绑定的逻辑放在 Session。

## 执行顺序

请求钩子按注册顺序执行，响应钩子按**相反**顺序执行，即洋葱模型：

```text
请求：RequestId → TenantHeader → 网络
响应：网络 → TenantHeader → RequestId
```

因此最外层的 middleware 最先看到请求、最后看到响应，适合放计时和审计。

## 中止请求

`on_request` 返回 `Err` 会中止该请求，**连接都不会建立**；`on_response` 返回 `Err` 会把
响应替换成这个错误。这可以用来实现请求白名单、配额检查或响应内容校验：

```rust,ignore
fn on_request(&self, req: MiddlewareRequest) -> Result<MiddlewareRequest> {
    if !self.allowed_hosts.contains(host_of(&req.url)) {
        return Err(/* 你的错误 */);
    }
    Ok(req)
}
```

## 调用次数与边界

- **每个请求各调用一次**：连续发三个请求，请求钩子和响应钩子各执行三次。
- **重试**：重试策略产生的重复发送同样会经过钩子，因此计数类 middleware 统计的是实际
  发出的次数，不是调用方发起的逻辑请求数。
- **流式响应**：`send_streaming()` **只执行请求钩子，不执行响应钩子**。因为响应体是增量
  读取的，没有一个"完整响应"可以交给 `on_response`。需要检查响应内容时，用普通 `send()`。
- **与 HSTS 的先后**：middleware 对 `url`、`method` 和 `body` 的修改先生效，HSTS 升级在
  其后应用。也就是说，在 middleware 里把 URL 改成 `http://`，该升级仍然会发生。

## 与指纹的关系

middleware 直接改 `headers` 会绕过 preset 的 header order 安排：新插入的头会落在顺序末尾，
而不是真实浏览器发送该头的位置。注入自定义头（如 `x-request-id`）通常无妨，但改写浏览器
本身就会发送的头（`accept`、`accept-language`、`user-agent` 等）时，应改用 Client 的默认
头配合 header order，或确认改动后的顺序仍与目标浏览器一致。
