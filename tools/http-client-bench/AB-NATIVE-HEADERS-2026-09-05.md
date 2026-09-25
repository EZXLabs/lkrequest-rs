# H2 原生请求与响应头单次解析 A/B（2026-09-05）

## 优化内容

本轮在自研 HPACK decoder 基线上实现两项不改变请求 wire bytes 的对象转换优化：

1. 高层 H2 请求直接构造 `NativeH2Request`，有序 header 使用 `HeaderName/HeaderValue` 保存，跳过 `http::Request<()>`、每个 header 的 `String` 分配以及 request body 的 oneshot handoff；
2. driver 在完成响应字段校验时直接生成最终 `HeaderMap`，上层 response builder 不再重新校验、重新解析并逐项插入相同 header。

旧兼容入口和 streaming API 保留；普通 `RequestBuilder::send()` 的 H2 路径使用新的直接入口。

## 指纹边界

- 请求 method、URI、header order、重复 header、pseudo-header order、HPACK policy、动态表状态、HEADERS/DATA frame 和 write policy 均未改变；
- 字节级测试使用两个独立、相同 profile 的 engine，分别通过旧 `http::Request` 入口和新 native 入口编码包含重复 cookie 与 body 的请求，并断言完整 frame bytes 相等；
- 响应优化只影响接收后的内存表示，不影响客户端发送字节；
- 本轮没有启用 H2 write batching，默认 batch size 仍为 `1`。

## Linux 七轮交替 A/B

- 主机：Ubuntu 24.04 KVM，Linux `6.8.0-117-generic`；
- 协议：loopback h2c prior knowledge；
- 每轮：200,000 请求、1 KiB body、并发 32、单 Session、单连接；
- runtime：客户端 1 worker，服务端 2 workers；
- CPU affinity：客户端固定 CPU 1，服务端固定 CPU 2-3；
- 顺序：旧→新、新→旧交替；
- 两个 variant 所有轮次均为 0 failures。

| Variant | 七轮吞吐范围 | 中位吞吐 | 中位 p50 | 中位 p95 | 中位 p99 | 中位 CPU/request |
|---|---:|---:|---:|---:|---:|---:|
| 自研 HPACK 基线 | 21,044–22,175 req/s | 21,453 req/s | 1,522 us | 1,682 us | 1,775 us | 46.61 us |
| native request + parsed response | 22,306–24,088 req/s | 23,417 req/s | 1,381 us | 1,604 us | 1,743 us | 42.66 us |
| 变化 | — | **+9.2%** | **-9.3%** | **-4.6%** | **-1.8%** | **-8.5%** |

优化版第 2–4 轮出现过较高的 p99，但后续三轮恢复到 1,651–1,674 us；使用七轮中位数后没有尾延迟回归。吞吐和 CPU/request 的改善方向一致，说明收益主要来自减少每请求对象转换、分配和解析，而不是服务端或计时噪声。

## 正确性验证

- `cargo test -p lkh2`：247 tests 和 doctest 通过；
- `cargo test -p lkrequest`：Tier 0 单元、集成和 doctest 全部通过，Tier 2 测试保持 ignored；
- `cargo test -p lkrequest --test e2e_h2c_upgrade`：8 tests 通过；
- `cargo test -p lkrequest --test fingerprint_regression`：28 tests 通过；
- `cargo test -p http-client-bench`：4 tests 通过；
- `cargo clippy -p lkh2 -p lkrequest --all-targets -- -D warnings`：通过；
- `cargo fmt --all -- --check` 与 `git diff --check`：通过。

## 原始结果

- 目录：`benchmark-results/linux-2026-09-05-native-fastpath/`；
- 七轮归档：`native-fastpath-ab-results-7-rounds.tar.gz`；
- SHA-256：`2c2e54bc172c88383409445889031b6cb3c84803bd1a70847fa799d59c35d2f3`。

