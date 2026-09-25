# 快速开始

本章介绍如何直接在现有 Rust 项目中添加 lkrequest，并完成第一个同步、异步和浏览器 preset 请求。所有示例都假定你只访问已获授权的目标。

## 添加 Cargo 依赖

lkrequest 尚未通过 crates.io 发布完整依赖图。普通用户无需手动 clone workspace，可以直接引用公开 Git 仓库：

```toml
[dependencies]
lkrequest = { git = "https://github.com/EZXLabs/lkrequest-rs" }
```

也可以使用 Cargo 命令：

```bash
cargo add lkrequest --git https://github.com/EZXLabs/lkrequest-rs
```

这已经足够使用同步 `lkrequest::blocking` API。Tokio 是 lkrequest 的内部实现依赖，但同步用户不需要在自己的 `Cargo.toml` 中直接声明 Tokio。

启用 HTTP/3/QUIC：

```toml
lkrequest = { git = "https://github.com/EZXLabs/lkrequest-rs", features = ["quic-h3"] }
```

Git 默认跟随仓库默认分支。生产项目应固定经过验证的 commit，以避免依赖随分支推进而变化：

```toml
lkrequest = { git = "https://github.com/EZXLabs/lkrequest-rs", rev = "<tested-commit>" }
```

构建机需要 Rust/Cargo。加密依赖在部分平台还需要 NASM、CMake 和 libclang；只有生成 C header 时需要 `cbindgen`。

## 第一个同步请求

同步 API 在库内部创建专用 Tokio runtime。不要从已有异步 runtime 内调用 blocking `send()`：

```rust,ignore
use lkrequest::{blocking, preset, Client};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let async_client = Client::builder()
        .preset(preset::chrome_154())
        .use_native_certs()
        .build();
    let client = blocking::Client::new(async_client);

    let session = client.session().build();
    let response = session.get("https://example.com").send()?;
    println!("{}", response.status());
    Ok(())
}
```

## 第一个异步请求

异步 API 需要用户提供 async runtime。使用 Tokio 时，再额外添加：

```toml
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

应显式选择 preset，而不是依赖内部默认值：

```rust,ignore
use lkrequest::{preset, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .preset(preset::chrome_154())
        .use_native_certs()
        .build();

    let session = client.session().build();
    let response = session.get("https://example.com").send().await?;

    println!("{:?} {}", response.negotiated_version(), response.status());
    println!("{}", response.text()?);
    Ok(())
}
```

`Client` 保存可共享的指纹和连接配置；`Session` 保存 Cookie、连接池、代理和协议发现状态；`RequestBuilder` 保存单次请求选项。

Firefox 156 可使用 `preset::firefox_156()`，该 preset 提供 TLS/H2，不提供 QUIC/H3。
浏览器版本列表、请求头配置和验证边界见[选择浏览器 preset](guides/choosing-a-preset.md)。

## Feature 选择

| Feature | 默认 | 何时启用 |
|---|---:|---|
| `quic-h3` | 否 | 需要 HTTP/3、QUIC、H3 preset 或 SOCKS5 UDP |
| `doh` | 否 | 需要内置 DNS over HTTPS resolver |
| `telemetry` | 否 | 需要运行时指标；会增加观测开销 |
| `synthetic-fp` | 否 | 仅用于合成指纹研究；输出不代表真实浏览器 |
| `network-e2e` | 否 | 只编译公网集成测试，不是生产能力 feature |

HTTP/2 始终使用 `lkh2`，无需选择 backend。`h2-native` 当前只为兼容旧版 Cargo 配置而保留，不是用户需要启用、关闭或选择的功能；该兼容名称将在 `0.3.0` 完全删除。旧项目如果显式写了 `features = ["h2-native"]`，应现在直接移除。

## 从源码参与开发

只有修改 lkrequest、运行 workspace 测试或维护底层 patched transport 时，才需要 clone 完整仓库：

```bash
git clone --recurse-submodules https://github.com/EZXLabs/lkrequest-rs.git
cd lkrequest-rs
cargo test --workspace
```

如果 clone 时没有初始化 submodule，执行 `git submodule update --init --recursive`。

## 下一步

- 不确定下一步：进入[使用场景导航](guides/README.md)
- [请求与响应](guides/requests/README.md)
- [Client、Session 与连接复用](guides/client-session.md)
- [代理与 DNS](guides/networking.md)
- [HTTP 协议策略](guides/protocols.md)
- [选择浏览器 preset](guides/choosing-a-preset.md)
- [高级应用](guides/advanced/README.md)
- [故障排查](guides/troubleshooting.md)
- [C ABI 与其他语言绑定](guides/ffi.md)
- 仅在需要理解状态边界时阅读[Client、Session 与 Request](guides/object-model.md)
