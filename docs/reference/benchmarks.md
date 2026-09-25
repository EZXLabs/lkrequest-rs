# 当前 benchmark 状态

本页于 **2026-09-06** 重新核对。此前展示的 Linux 跨客户端矩阵采集于自研 HPACK decoder 和 native request/response fast path 完成之前，已经不能代表当前代码，因此不再将其作为“最新性能结论”。

## 当前可以确认的结果

当前实现最终状态下最新的直接测量，是 `tools/http-client-bench/AB-NATIVE-HEADERS-2026-09-05.md` 中的 Linux 七轮 A/B。该测试已经包含自研 HPACK decoder，并验证随后加入的 native request/response fast path：

- Ubuntu 24.04 KVM，kernel `6.8.0-117-generic`；
- loopback h2c prior knowledge，无 TLS、DNS、代理、压缩或重定向；
- 200,000 requests、1 KiB response、并发 32；
- 单 Session、单 H2 连接、客户端 1 worker、服务端 2 workers；
- 七轮交替顺序，两个 variant 均为 0 failures；
- 默认 H2 write batch size 为 `1`。

| Variant | 中位吞吐 | p50 | p95 | p99 | CPU/request |
|---|---:|---:|---:|---:|---:|
| 自研 HPACK 基线 | 21,453 req/s | 1,522 us | 1,682 us | 1,775 us | 46.61 us |
| native request + parsed response | 23,417 req/s | 1,381 us | 1,604 us | 1,743 us | 42.66 us |
| 变化 | **+9.2%** | **-9.3%** | **-4.6%** | **-1.8%** | **-8.5%** |

这个结果能够证明 native fast path 在指定 workload 下减少了对象转换、分配和重复 header 解析成本。它不建立当前 lkrequest 相对 Hyper 或 reqwest 的比例。

## 已失效的旧结论

旧页面引用的五轮跨客户端矩阵中，lkrequest c32 为 11,597 req/s，并据此得出“只有 reqwest 的 34.0%”等结论。该矩阵适合记录 `TCP_NODELAY` 修正和早期瓶颈，但随后至少发生了两项直接影响结果的实现变化：

1. 使用自研 HPACK decoder 替代 `fluke-hpack`，相同 Linux profiler workload 中吞吐从 11,023 提升至 20,016 req/s；
2. native request/response fast path 又在其基线上将中位吞吐从 21,453 提升至 23,417 req/s。

这些数字来自不同的 A/B workload，不能相乘，也不能直接套用到旧跨客户端矩阵。旧矩阵现仅作为历史诊断数据保留。

## 当前缺口

截至 2026-09-06，仓库中没有一组同时满足以下条件的最终态跨客户端结果：

- 使用包含自研 HPACK 与 native fast path 的当前 lkrequest；
- 与 Hyper、reqwest 使用完全相同的二进制、workload 和运行顺序；
- 覆盖标准 c1/c8/c32/c128 与 1 MiB 场景；
- 保留逐轮 JSON/JSONL、p50/p95/p99、CPU、RSS、失败数和连接数；
- 将原始归档纳入公开可验证产物。

因此当前正确结论是：**已有 A/B 证明当前实现显著快于旧实现，但尚无证据给出当前版本相对主流客户端的正式排名或百分比。**

## 发布状态

最新 A/B 报告记录了原始归档名称和 SHA-256，但归档本身不在公开源码树中，因此仍为 `engineering evidence / not publishable`。完成最终态标准矩阵并公开原始结果后，才能将新数据标记为正式当前基线。

