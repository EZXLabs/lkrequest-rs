# Benchmark 历史与状态

机器可读索引位于 `docs/data/benchmark-index.toml`。`current` 表示当前工程参考基线，`publishable` 表示是否满足公开引用和宣传所需的证据门槛，两者不是同一概念。

| 日期 | 数据集 | 状态 | 当前 | 可发布 | 说明 |
|---|---|---|---:|---:|---|
| 2026-09-05 | Linux native request/response fast-path A/B | current-engineering-baseline | 是 | 否 | 当前实现最终路径的最新直接 A/B；不是完整跨客户端矩阵，原始归档未进入公开树 |
| 2026-09-05 | Linux self-hosted HPACK decoder A/B | superseded-engineering-ab | 否 | 否 | 证明 HPACK 优化，但早于 native fast path |
| 2026-09-05 | Linux HTTP/2 corrected cross-client baseline | historical-cross-client-baseline | 否 | 否 | `TCP_NODELAY` 修正后的五轮矩阵，但早于后续 HPACK 与 native fast path 优化 |
| 2026-09-05 | Windows HTTP/2 diagnostic baseline | superseded | 否 | 否 | 修正前数据，只保留用于解释测量污染 |
| 2026-09-05 | HTTP/2 dispatch batching A/B | engineering-ab | 否 | 否 | 验证实现 trade-off，不证明浏览器 wire parity |

当前证据摘要见[当前 benchmark 状态](../../reference/benchmarks.md)。新增数据集时，应先按[方法与发布门槛](methodology.md)归档环境、workload 和原始结果，再更新 TOML 索引与本页。
