# 兼容性与环境边界

## Rust 与构建工具

- workspace 同时包含 Rust 2021 和 Rust 2024 edition crate；edition 不是 MSRV 声明。
- 当前尚未完成受控最低 Rust 版本验证，因此 Cargo metadata 暂不声明 `rust-version`。
- `deps/quinn` 与 `deps/h3` submodule 必须初始化，并使用仓库固定的 patched revision。
- 部分加密构建路径需要 NASM、CMake 和 libclang。
- FFI header 生成需要 `cbindgen`；没有 cbindgen 时 Rust crate 仍可构建。

## 平台

核心 Rust workspace 面向 Windows、Linux 和 macOS 类平台，但发布包、动态库命名、系统证书和 socket 行为都与 target 相关。没有在 artifact matrix 中列出的 target，不应被描述为已发布或已 smoke-tested。

## 协议环境

- H2 依赖目标通过 ALPN 或明确 h2c 场景支持 HTTP/2。
- H3 依赖 UDP 可达、目标支持 QUIC/H3，并启用 `quic-h3`。
- HTTP/SOCKS5 代理支持 TCP 不代表支持 QUIC；QUIC-over-SOCKS5 还要求 UDP relay。
- ECH 与 HTTPS/SVCB discovery 依赖 resolver 能查询对应记录，并且 DNS 视图与实际出口兼容。
- `socks5h` 只改变目标 A/AAAA 的解析位置，不自动远程化额外 HTTPS record 查询。

## 指纹兼容性

浏览器 milestone、平台、Finch、请求类型、session state、GREASE 和网络路径都会改变可观察行为。preset 应视为一个经过版本化审阅的配置快照，而不是“任何环境下都与浏览器完全相同”的保证。

完整分级见[指纹 preset 支持与验证矩阵](presets.md)。

TCP SYN 由运行平台的内核生成。`TcpFingerprint` 可调整部分 socket 参数，但窗口与缩放只能间接影响，MSS 当前仅在 Linux 应用，options 列表不会改写真实 SYN。Windows、Linux、macOS 的逐项支持及代理边界见 [TCP 指纹的平台支持与限制](tcp-fingerprint.md)。
