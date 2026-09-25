# Summary

[文档首页](README.md)

# 用户手册

- [快速开始](getting-started.md)
- [使用场景导航](guides/README.md)
- [理解 Client、Session 与 Request](guides/object-model.md)
- [请求配置](guides/requests/README.md)
  - [请求体](guides/requests/bodies.md)
  - [流式上传](guides/requests/streaming-upload.md)
  - [响应处理](guides/requests/responses.md)
- [Client、Session 与连接复用](guides/client-session.md)
- [代理与 DNS](guides/networking.md)
- [HTTP 协议策略](guides/protocols.md)
- [选择浏览器 preset](guides/choosing-a-preset.md)
- [WebSocket](guides/websocket.md)
- [认证与证书](guides/auth-and-certificates.md)
- [资源限制与安全边界](guides/limits.md)
- [C ABI 与其他语言绑定](guides/ffi.md)
- [高级应用](guides/advanced/README.md)
  - [SessionPool 与 ProxyPool](guides/advanced/high-throughput.md)
  - [ProxyPool 轮转与动态生成](guides/advanced/proxy-pool.md)
  - [协议发现与回退](guides/advanced/protocol-discovery.md)
  - [指纹随机化](guides/advanced/randomization.md)
  - [Middleware](guides/advanced/middleware.md)
  - [诊断与可观测性](guides/advanced/observability.md)
- [版本升级与迁移](guides/upgrading.md)
- [故障排查](guides/troubleshooting.md)

# 规格参考

- [Preset 支持与验证矩阵](reference/presets.md)
- [功能与协议能力](reference/capabilities.md)
- [兼容性与支持边界](reference/compatibility.md)
- [当前 benchmark 状态](reference/benchmarks.md)

# 开发者手册

- [crate 分层与边界](development/crate-layout.md)
- [Crate 功能与选型](development/crates.md)
- [自定义指纹与验证](development/fingerprint-research.md)
- [HTTP/2 性能分析](development/http2-performance.md)
- [HTTP/2 Write Batching 与指纹边界](development/h2-write-batching.md)
- [测试策略与环境](development/testing.md)
- [Benchmark 方法与发布门槛](development/benchmarks/methodology.md)
  - [标准 benchmark 场景](development/benchmarks/scenarios.md)
  - [Benchmark 历史与状态](development/benchmarks/history.md)
- [文档维护与生成](development/documentation.md)
- [发布产物与生成文件](development/artifacts.md)
