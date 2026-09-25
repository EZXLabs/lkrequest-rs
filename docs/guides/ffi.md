# C ABI 与其他语言绑定

`lkrequest-ffi` 将 Client、Session、Request、Response、StreamingResponse、ProxyPool、SessionPool 和 Multipart 暴露为稳定 opaque handles。完整符号和所有权规则见 crate 根目录的 `lkrequest-ffi/README.md`。

## 构建动态库

```bash
cargo build -p lkrequest-ffi --release
```

需要 H3/QUIC ABI 时：

```bash
cargo build -p lkrequest-ffi --release --features quic-h3
```

平台动态库名称由 Cargo target 决定，例如 Windows DLL、Linux `.so` 或 macOS `.dylib`。绑定应从发布包或实际 target 目录解析产物，不要硬编码开发机绝对路径。

## 生成 header

`lkrequest-ffi/include/lkrequest.h` 是未跟踪构建产物。CI、发布任务或绑定构建必须自行生成：

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

正常 `cargo build` 在找到 `cbindgen` 时也会由 `build.rs` 生成 header；未安装时 Rust crate 仍可构建，但不会产生 header。

## 所有权规则

- 每个 opaque handle 必须使用对应的 `*_free` 释放。
- Client、Session 和 Op 可以共享；Request 与 StreamingResponse 是单 owner。
- borrowed pointer 由产生它的 handle 所有，不能由调用方释放。
- streaming chunk pointer 会在下一次修改性读取、close 或 free 后失效。
- async API 返回 Op；绑定必须等待完成并使用匹配的 `take_*` 取得结果。
- 错误 handle 也必须按 API 约定读取和释放，不能只记录裸指针。

## 绑定作者最低验证

```bash
cargo test -p lkrequest-ffi
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
```

修改导出面后还应重新生成 header、比较 ABI，并运行 `lkrequest-ffi/tests/c_smoke.c`。不要提交生成的 `lkrequest.h`。
