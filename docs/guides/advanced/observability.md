# 诊断与可观测性

lkrequest 提供请求尝试摘要、单次请求 diagnostics、`tracing` 事件、可选 telemetry 指标和 TLS key log。它们的成本、敏感度和使用目的不同，不应默认全部开启。

## 能力选择

| 能力 | 开启方式 | 适合回答 | 敏感度/成本 |
|---|---|---|---|
| Request diagnostics | `.collect_diagnostics(true)` | DNS/TCP/TLS/QUIC/TTFB/总耗时、协议、remote address | 单请求额外采集 |
| Attempt summary | `.send_with_attempt_summary()` 或 `.observe_attempts()` | HTTP 提交、建链、恢复授权、有效上限与拒绝原因 | 固定大小快照，不含 URL、headers 或 body |
| `tracing` | 应用安装 subscriber | 连接、协议选择、retry/fallback 的事件链 | 取决于日志级别，可能包含目标信息 |
| Telemetry | `telemetry` feature | 全局请求、连接和带宽计数 | 默认关闭，有运行时观测成本 |
| TLS key log | `ClientBuilder::keylog()` | Wireshark 解密 TLS 流量 | 极高敏感度，相当于会话解密材料 |

## 单次请求 diagnostics

```rust,ignore
let response = session
    .get("https://example.com")
    .collect_diagnostics(true)
    .send()
    .await?;

if let Some(diagnostics) = response.diagnostics() {
    println!("{diagnostics:#?}");
}
```

复用连接时 DNS、TCP、TLS 或 QUIC 阶段可能为空，这是正常现象。需要分析 fresh connection 时，应使用未访问过的 origin 或明确清理测试状态，而不是把空阶段当作采集失败。

| 字段 | HTTPS over H1/H2 | H3 |
|---|---|---|
| `dns_ms` | 本地地址解析耗时 | 本地地址解析耗时，代理远程解析时为空 |
| `tcp_ms` | TCP 建连耗时 | 空 |
| `tls_ms` | TCP 上的 TLS 握手耗时 | 空，TLS 已包含在 QUIC 握手中 |
| `quic_ms` | 空 | QUIC 握手完成耗时，包含内部 TLS，排除 DNS、代理隧道和 H3 控制流初始化 |
| `remote_addr` | 实际连接地址 | QUIC 对端地址；代理远程解析时不暴露内部占位地址，保留空值 |
| `cipher_suite` | 协商的 TLS 加密套件 | 同样提供，包括复用连接 |

`quic_ms` 只记录当前请求建立的连接，不把历史握手耗时带到复用请求。
0-RTT 可提前发送，但只有握手成功完成后才记录这个值；诊断不会增加额外等待。
H2/H3 竞速候选的记录相互隔离，结果归属于最终完成请求的候选。
各字段不是可直接相加的串行时间账本，整体等待应读取 `total_ms`。
FFI diagnostics JSON 在 `schema_version: 1` 中增加可空的 `quic_ms` 字段；调用方应容忍新增字段。
Rust 调用方若手写完整的 `RequestDiagnostics` 结构体字面量，需要补上 `quic_ms`，
或使用 `..Default::default()` 初始化未指定字段。C ABI 的函数与结构布局没有变化。

HTTP/1.1 在响应头返回前收到的 TLS 致命告警通过 `Error::as_tls_alert()` 读取，原始原因保留在
`Error::source()` 链中。此时 `phase()` 为 `HttpRequest`，不表示握手前失败，不能据此
安全重发非幂等请求。C API 返回 `LK_ERR_TLS` 和 HTTP 请求阶段，消息包含告警名称与编号。

## 请求尝试摘要

摘要统计一次公开请求调用内发生的尝试，不要求开启 diagnostics、`telemetry` 或有限次数上限。失败结果也可以返回摘要：

```rust,no_run
use lkrequest::Client;

# async fn example() {
let session = Client::builder().build().session().build();
let (result, summary) = session.get("https://example.com")
    .send_with_attempt_summary().await;
println!("HTTP={}, extra={}, connect={}, outcome={:?}, denial={:?}",
    summary.http_submissions(),
    summary.extra_http_submissions(),
    summary.connect_initiations(),
    summary.outcome(),
    summary.denial_reason());
if let Err(error) = result {
    eprintln!("{error}");
}
# }
```

`http_submissions()` 包含初次提交、重定向和额外提交；`extra_http_submissions()` 是其中消耗重发额度的部分。`recoveries()` 统计获准的恢复决策，即使之后在提交前被取消；它不等于实际重发次数。`connect_initiations()` 包含失败或落败的建链，不代表当前存活连接数。所有提交计数都不能证明服务端已收到或执行请求。

`effective_limits()` 返回已解析的配置及其来源，配置尚未解析或无效时为 `None`。`denial_reason()` 解释阻止继续恢复的原因，例如 `ExtraHttpLimit` 或 `ConnectLimit`，不会替换原来的响应或错误。`Succeeded` 表示返回了响应，也可能是 HTTP 4xx/5xx。

### 观察取消

```rust,no_run
use lkrequest::Client;

# async fn example() {
let session = Client::builder().build().session().build();
let (request, observer) = session.get("https://example.com").observe_attempts();
let task = tokio::spawn(request.send());
task.abort();
let _ = task.await;
let summary = observer.snapshot();
assert!(summary.outcome().is_final());
# }
```

运行中的快照可能继续变化；取消后等待任务退出，才能确认最终计数。observer 只读，保留它不会延长请求的发送权限。使用 `send_streaming_with_attempt_summary()` 时，摘要在响应 headers 返回时固定；之后的 body 错误应按流式读取结果处理。blocking 请求也提供对应摘要与 observer API。

C 调用方先用 `lk_request_enable_attempt_summary` 开启收集，再从 Response、StreamingResponse、Error 或 Op 复制 JSON；Op 取消和结果取走后仍能读取摘要。JSON 缓冲区和句柄生命周期规则见[C ABI 指南](../ffi.md#次数上限与请求诊断)。

## Telemetry

启用：

```toml
lkrequest = { git = "https://github.com/EZXLabs/lkrequest-rs", features = ["telemetry"] }
```

`telemetry::metrics_snapshot()` 返回请求、失败、活动连接、总连接和收发字节计数。字节计数可能先在连接内累计，并在 request boundary、显式 flush 或连接关闭时汇总；读取时要说明采样时点。

## Tracing 与日志

库只发出 `tracing` 事件，由应用选择 subscriber、过滤级别和输出位置。生产环境应默认过滤 URL query、Authorization、Cookie、proxy credential 和业务 payload，不能直接上传 debug 日志。

## TLS key log

key log 只应用于受控诊断：

- 写入访问受限的临时目录；
- 与对应 capture 使用相同会话；
- 不进入 Git、CI artifact、issue 或聊天记录；
- 分析完成后安全删除；
- 公共 benchmark 默认关闭，并在环境字段中明确记录。

完整 telemetry 示例见公开仓库的 `lkrequest/examples/telemetry_metrics.rs`。

