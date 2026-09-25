# 发布产物规格

本页定义发布产物应记录的字段。当前 public tree 尚没有满足该 schema 的完整跨平台 artifact index，因此以下内容是可验证合同，不是已完成发布矩阵。

## 产物类型

| 类型 | 典型文件 | 是否跟踪 |
|---|---|---:|
| Rust source | Git tag/source archive | 是 |
| FFI dynamic library | `lkrequest_ffi.dll`、`liblkrequest_ffi.so`、`liblkrequest_ffi.dylib` | 否，CI 构建 |
| C header | `lkrequest.h` | 否，cbindgen 生成 |
| package archive | 平台压缩包 | 否，release job 组装 |
| checksum | `SHA256SUMS` 或单文件 SHA-256 | 否，release job 生成 |

## 每个平台必须记录

- release version 与 git commit；
- target triple、build profile 和 Cargo features；
- 生成该文件的 CI job；
- artifact 内路径与 SHA-256；
- signing status；
- built、smoke-tested、integration-tested、package-verified、published 中实际完成的最高验证状态。

编译成功不等同于安装包验证，安装包验证也不等同于已签名或已公开发布。报告必须分别列出。

## FFI header

`lkrequest-ffi/include/lkrequest.h` 必须由 CI/发布 workspace 自行生成：

```bash
cd lkrequest-ffi
cbindgen . --config cbindgen.toml > include/lkrequest.h
```

任何 job 都不得要求该文件预先存在于 Git。header 应与同一 commit、同一 feature 组合构建的动态库一起打包和 smoke-test。

## 当前 CI 实际产出

GitLab 流水线目前产出的内容如下，可作为上表的现状对照：

| Job | 产物 | 触发条件 |
|---|---|---|
| `build-ffi-linux` | `artifacts/linux-x86_64/` | 常规流水线 |
| `build-ffi-windows` | `artifacts/windows-x86_64/` | 常规流水线 |
| `build-ffi-linux-musl` | `artifacts/linux-x86_64-musl/` | 常规流水线 |
| `release` | 三个平台的动态库加 `lkrequest.h` | tag 匹配 `v*` |
| `github-sync` | `release-assets/` | 公开同步 |
| `crates-io-publish` | crates.io 发布 | tag 匹配 `public-v*`，手动触发 |
| `doc` | `target/book/`、`target/doc/` | 见[文档维护与生成](documentation.md)，保留 7 天 |
| `bench-*` | 各自的 `bench_*.txt` | benchmark 流水线 |

`crates-io-publish` 先用 `tools/cleaner` 生成 sanitized 快照再发布，因此发布内容与
仓库工作区不是同一棵树。当前只有 `lktls` 和 `lkh2` 能够通过打包检查，其余 crate 仍被
patched `quinn`/`h3` fork 阻塞，详见内部发布记录。

签名与跨平台校验尚未纳入流水线，因此上表中的产物目前最高只能标记为 built 或
smoke-tested，不能标记为 signed 或 published。

机器可读字段定义见 `docs/data/artifact-schema.toml`。
