# 测试策略与环境

本文档说明 lkrequest 工作区的测试分层、覆盖率与性能门禁，以及如何在不依赖公网的情况下跑默认 CI。

## 测试分层（Tier）

| Tier | 说明 | 何时运行 |
|------|------|----------|
| **Tier 0** | 仅 `127.0.0.1` / `::1` 或内存，嵌入式 HTTP(S) 服务 | 默认 `cargo test --workspace`，PR / CI 必过 |
| **Tier 1** | 本机 Docker 等（如 TLS-Attacker、mitm 代理），仍不访问公网 | 本地或自建 runner，手动或单独 workflow |
| **Tier 2** | 公网主机（browserleaks、Cloudflare、httpbingo 等），可选经 `TEST_PROXY` | 需显式开启，见下文 |

## 环境变量

| 变量 | 含义 |
|------|------|
| `TEST_ALLOW_NETWORK=1` | 文档约定：运行 Tier 2 前在 CI/本地显式开启；与 `#[ignore]` 的「网络 E2E」配套使用 |
| `TEST_PROXY` | Tier 2 使用的 HTTP 代理（如 `http://127.0.0.1:7897`）；空字符串可表示禁用代理（视具体测试而定） |
| `CI=true` | 典型 CI 环境；默认流水线仍只跑 Tier 0（不 `--include-ignored`） |

运行 **所有** 含 `#[ignore]` 的测试（含外网）：

```bash
cargo test --workspace -- --include-ignored
```

建议在可访问外网且已配置代理的机器上执行，并设置 `TEST_ALLOW_NETWORK=1` 作为团队约定。

## Cargo feature：`network-e2e`（lkrequest）

集成测试 crate 可启用可选特性以编译仅在网络环境下有意义的辅助代码：

```bash
cargo test -p lkrequest --features network-e2e
```

默认 **不** 启用；CI 标准命令不携带该 feature。

## 覆盖率门禁（目标）

| 指标 | 目标 |
|------|------|
| `lkrequest` + `lktls` 行覆盖率 | ≥ **85%**（引入门禁时可从 **80%** 起，再抬升） |
| 分支覆盖率 | ≥ **70%** |
| PR | 在工具支持时优先使用 diff 覆盖；否则至少保证修改文件覆盖率不回退 |

使用 [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)（与 CI 一致）：

```bash
cargo llvm-cov test -p lktls -p lkrequest -p lkh2 -p lkprofile --fail-under-lines 25
```

阈值 `25` 为初始下限，应在仓库内逐步提高。完整配置见 [`.github/workflows/test.yml`](https://github.com/EZXLabs/lkrequest-rs/blob/main/.github/workflows/test.yml)。

## 性能基线（可选 CI）

Criterion 基准对 **缓存的 baseline** 回归超过约 **3%** 时可配置为失败；仅在 **同类 runner** 上对比有意义。详见 workflow 中 `bench` job（`workflow_dispatch` / `schedule`）。

## 验收清单

- 无出站网络（或无法解析公网）时：`cargo test --workspace` 全绿。
- `llvm-cov` 满足工作流中的下限。
- Tier 2：`cargo test --workspace -- --include-ignored` 在可联网环境下一键回归。

## `lkrequest-ffi` 开发者验证

FFI 层除了常规 Rust 单元/集成测试，还需要额外关注头文件、C ABI 和 `clippy` 零告警。

推荐本地提交前至少执行：

```bash
cargo fmt --all
cargo test -p lkrequest-ffi
cargo clippy -p lkrequest-ffi --all-targets --all-features -- -D warnings
```

若修改了 FFI 导出面或注释，需重新生成头文件：

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

说明：

- 正常 `cargo build` / `cargo test` 已会通过 `lkrequest-ffi/build.rs` 自动刷新 `include/lkrequest.h` 与 `generated.h`
- 手动执行 `cbindgen` 主要用于只重刷头文件、不跑完整编译时

Windows 上可额外运行现有 C 烟测：

```powershell
$env:PATH='D:\Misc\tools\cygwin\bin;' + $env:PATH
& 'D:\Misc\tools\cygwin\bin\x86_64-w64-mingw32-gcc.exe' `
  -I lkrequest-ffi\include `
  -o target\debug\c_smoke.exe `
  lkrequest-ffi\tests\c_smoke.c `
  target\debug\lkrequest_ffi.dll.lib

$env:PATH='D:\Project\lkrequest\target\debug;D:\Misc\tools\cygwin\bin;' + $env:PATH
& 'D:\Project\lkrequest\target\debug\c_smoke.exe'
```

当前 `lkrequest-ffi` 集成测试按职责划分为：

- `tests/request_api_basics.rs`：基础 sync/async 请求与响应 getter
- `tests/streaming_diagnostics_and_configuration.rs`：streaming、diagnostics、builder 配置
- `tests/ffi_contract_edge_cases.rs`：单次消费、类型不匹配、debug-registry 边界
- `tests/v2_capabilities_smoke.rs`：Session/ProxyPool/SessionPool/Multipart/DNS/logging callback
