# 诊断与可观测性

lkrequest 提供单次请求 diagnostics、`tracing` 事件、可选 telemetry 指标和 TLS key log。它们的成本、敏感度和使用目的不同，不应默认全部开启。

## 能力选择

| 能力 | 开启方式 | 适合回答 | 敏感度/成本 |
|---|---|---|---|
| Request diagnostics | `.collect_diagnostics(true)` | DNS/TCP/TLS/TTFB/总耗时、协议、remote address | 单请求额外采集 |
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

复用连接时 DNS、TCP 或 TLS 阶段可能为空，这是正常现象。需要分析 fresh connection 时，应使用未访问过的 origin 或明确清理测试状态，而不是把空阶段当作采集失败。

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

