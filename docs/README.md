# lkrequest 文档

本目录保存随公开源码发布的正式文档，分为两册：**用户手册**（`guides/` 与 `reference/`，重点是应用与场景）和**开发者手册**（`development/`，重点是架构与实现）。文档中的行为说明必须与当前代码、测试和发布能力一致，并随相关实现一起评审。

## 面向用户

用户文档以“要完成什么任务”为入口，示例优先，概念只用于解释正确的对象和行为边界。

### 开始使用

- [项目概览与快速开始](https://github.com/EZXLabs/lkrequest-rs/blob/main/README-zh.md)
- [完整快速开始](getting-started.md)
- [使用场景导航](guides/README.md)

### 请求与网络

- [请求配置](guides/requests/README.md)
- [流式上传](guides/requests/streaming-upload.md)
- [Client、Session 与连接复用](guides/client-session.md)
- [代理与 DNS](guides/networking.md)
- [HTTP 协议策略](guides/protocols.md)
- [C ABI 与其他语言绑定](guides/ffi.md)

### 高级场景

- [SessionPool 与 ProxyPool](guides/advanced/high-throughput.md)
- [ProxyPool 轮转与动态生成](guides/advanced/proxy-pool.md)
- [协议发现与回退](guides/advanced/protocol-discovery.md)
- [指纹随机化](guides/advanced/randomization.md)
- [诊断与可观测性](guides/advanced/observability.md)

### 指纹、规格与问题定位

- [选择浏览器 preset](guides/choosing-a-preset.md)
- [Preset 支持与验证矩阵](reference/presets.md)
- [功能与协议能力](reference/capabilities.md)
- [兼容性与支持边界](reference/compatibility.md)
- [当前 benchmark 状态](reference/benchmarks.md)
- [版本升级与迁移](guides/upgrading.md)
- [故障排查](guides/troubleshooting.md)
- [理解 Client、Session 与 Request](guides/object-model.md)：仅在需要判断状态边界时阅读。

## 面向开发者

- [贡献指南](https://github.com/EZXLabs/lkrequest-rs/blob/main/CONTRIBUTING.md)
- [架构与 crate 边界](development/crate-layout.md)
- [Crate 功能与选型](development/crates.md)
- [测试策略、环境与验证命令](development/testing.md)
- [文档维护与生成](development/documentation.md)
- [发布产物与生成文件](development/artifacts.md)
- [自定义指纹与验证](development/fingerprint-research.md)
- [Benchmark 方法与发布门槛](development/benchmarks/methodology.md)
- [HTTP/2 性能与使用边界](development/http2-performance.md)
- [HTTP/2 Write Batching 与指纹边界](development/h2-write-batching.md)
- [安全策略与负责任使用](https://github.com/EZXLabs/lkrequest-rs/blob/main/SECURITY.md)
- [Linux HTTP/2 性能测试报告](https://github.com/EZXLabs/lkrequest-rs/blob/main/tools/http-client-bench/LINUX-RESULTS-2026-09-05.md)

## Crate 文档

- [`lkrequest`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkrequest/README.md)：高层 Client、Session 与请求 API；
- [`lktls`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lktls/README.md)：Sans-I/O TLS 与 ClientHello 指纹；
- [`lkh2`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkh2/README.md)：原生 HTTP/2、HPACK 与帧级指纹；
- [`lkh3`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkh3/README.md)：HTTP/3、QPACK 与 QUIC profile；
- [`lkquic`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkquic/README.md)：QUIC endpoint 与 backend 管理；
- [`lktls-quic`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lktls-quic/README.md)：`lktls` 与 Quinn 的 TLS bridge；
- [`lkmasque`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkmasque/README.md)：Sans-I/O 的 MASQUE CONNECT-UDP 线上格式与隧道状态机，只依赖 `thiserror`，可独立使用；I/O 桥接在 `lkrequest` 内；
- [`lkprofile`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkprofile/README.md)：抓包和 fingerprint profile 解析；
- [`lkrequest-ffi`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkrequest-ffi/README.md)：C ABI、所有权和异步操作模型。

完整 crate 分层、直接使用边界和 API reference 生成方式见 [Crate 功能与选型](development/crates.md)。

## 文档边界

- `docs/`：公开、正式、持续维护的用户指南、开发者指南和参考资料；
- `design/`：内部设计稿、实施 prompt、审计记录、阶段性分析和历史报告，由公开快照生成流程整体排除；
- crate 根级 rustdoc：API 参考和可编译示例；
- crate `README.md`：crate 定位、适用范围、feature、依赖边界和最小验证命令；
- `tools/*/README.md`：对应工具的使用和维护说明。

`design/` 中的内容不能直接复制到 `docs/`。实现完成后，应提取仍然有效且经过验证的行为，重写为不依赖内部背景、当前可执行的正式文档。设计稿中的计划、状态、内部路径、原始抓包和阶段性结论不构成公开承诺。

面向用户的稳定行为以 `docs/`、crate API 文档、当前源码和测试为准；发布流程通过 `tools/cleaner/public_manifest.toml` 保留 `docs/` 并排除整个 `design/`。
