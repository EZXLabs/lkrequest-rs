# 自研 HPACK 替换后 CPU 火焰图（2026-09-05）

## 结论

`fluke-hpack` 已从 `lkh2` 的生产依赖、开发依赖和锁文件中完全移除。使用相同 Linux 主机、相同二进制构建参数、相同 CPU 绑定和相同默认 H2 负载重新采样后，旧火焰图中的 `HuffmanDecoder::new` 建表热点消失，响应头 HPACK 分支从 48.30% 降至 3.21%，实际 Huffman 解码仅占 0.20% attributed CPU。

瓶颈已经转移到默认模式的逐请求 socket write：`send` 占 31.42%，`encode_and_write_frames` 占 33.69%。这与此前 `strace` 发现默认模式产生大量小 `sendto` 一致，也说明下一项性能优化应继续围绕显式 H2 write batching，而不是继续微调 Huffman 查表。

## 测试配置

- 主机：Ubuntu 24.04 KVM，Linux `6.8.0-117-generic`；
- 协议：loopback h2c prior knowledge；
- 负载：500,000 请求、1 KiB 响应、并发 32、单 Session、单 H2 连接；
- runtime：客户端 1 worker，服务端 2 workers；
- CPU affinity：客户端和 profiler 固定 CPU 1，服务端固定 CPU 2-3；
- 默认配置：H2 write batching 关闭，batch size 为 `1`；
- profiler：`gprofng collect app -p 10 -t 15s -F off`；
- 构建：release + debuginfo；
- 范围：只分析 CPU 性能，不测试 TLS、HTTP/2 或 TCP 指纹。

## 相同负载 A/B

两次运行均通过 500,000 个请求，0 failures，观察到 1 条 H2 连接。旧数据来自替换前的 `fluke-hpack` 二进制，新数据来自完全移除该 crate 后的自研 decoder 二进制。

| 指标 | `fluke-hpack` | 自研 HPACK | 变化 |
|---|---:|---:|---:|
| 吞吐 | 11,023 req/s | 20,016 req/s | **+81.6%** |
| p50 | 2,675 us | 1,496 us | **-44.1%** |
| p95 | 3,893 us | 1,715 us | **-55.9%** |
| p99 | 4,153 us | 1,850 us | **-55.5%** |
| user + system CPU / request | 84.90 us | 46.11 us | **-45.7%** |
| 峰值 RSS | 24.9 MiB | 24.9 MiB | 无变化 |

这是 profiler 下的单次 matched A/B，用于验证热点是否消失，不替代多轮、交替顺序的发布基准。Windows 三轮 A/B 的中位吞吐提升为 68.4%，方向与本次 Linux 结果一致。

## 新火焰图热点

以下为 inclusive attributed CPU time；父子调用路径重叠，不能相加：

| 调用路径 | CPU time | 总 CPU 占比 | 判断 |
|---|---:|---:|---|
| `lkh2::driver::driver_loop` | 7.21 s | 48.20% | driver 仍是主要执行分支，但占比已大幅下降 |
| `dispatch_waiting_requests` | 5.50 s | 36.76% | 默认逐请求派发成为主要 driver 成本 |
| `encode_and_write_frames` | 5.04 s | 33.69% | 成本基本由 socket write 主导 |
| socket `send` | 4.70 s | 31.42% | 当前最大热点 |
| `H2Engine::process` | 0.66 s | 4.41% | 响应处理不再主导 CPU |
| `HeaderDecoder::decode` | 0.48 s | 3.21% | 包含 header 输出分配和字符串转换 |
| `Decoder::decode_literal` | 0.08 s | 0.53% | 自研 literal 解码成本很低 |
| `huffman::decode` | 0.03 s | 0.20% | Huffman trie 遍历不再是瓶颈 |
| `send_with_redirects` | 5.10 s | 34.09% | 高层 pipeline 占比因 HPACK 消失而相对上升 |
| `send_h2_request` | 3.18 s | 21.26% | pool、oneshot、请求状态和响应适配仍可优化 |
| `build_native_response` | 0.65 s | 4.34% | header 校验和 `http` 类型构造有可见成本 |

## 与旧火焰图的变化

| 分支 | 旧占比 | 新占比 | 变化 |
|---|---:|---:|---:|
| `H2Engine::process` | 48.30% | 4.41% | -43.89 pp |
| 响应头 HPACK decode | 47.52% | 3.21% | -44.31 pp |
| `HuffmanDecoder::new` | 44.34% | 0% | 完全消失 |
| socket `send` | 17.04% | 31.42% | 相对占比上升，成为新主瓶颈 |
| `driver_loop` | 71.85% | 48.20% | -23.65 pp |

socket `send` 的绝对 CPU time从 2.41 秒上升到 4.70 秒，是因为 15 秒采样窗口内新版本完成的请求更多；其每请求成本没有因 HPACK 替换而增加。占比上升反映的是 HPACK 大热点消失后的瓶颈迁移。

## 正确性回归

- `cargo test -p lkh2`：245 个单元/集成测试和 1 个 doctest 通过；
- `cargo test -p lkrequest --test e2e_h2c_upgrade`：8 个测试通过；
- `cargo clippy -p lkh2 --all-targets -- -D warnings`：通过；
- `cargo fmt --all -- --check`：通过；
- HPACK 独立证据包括 RFC 7541 C.4/C.6 状态序列、`h2` 的已知 Huffman 字节向量和对 `h2` 服务端的端到端互操作测试。

## 原始文件

- `benchmark-results/linux-2026-09-05-hpack-self/gprofng-default-c32.json`；
- `benchmark-results/linux-2026-09-05-hpack-self/gprofng-functions.txt`；
- `benchmark-results/linux-2026-09-05-hpack-self/gprofng-calltree.txt`；
- `benchmark-results/linux-2026-09-05-hpack-self/default-c32.er/`；
- 完整归档 `new-flamegraph-results.tar.gz`，SHA-256 `af3c64c9cd40106fdb5c97fa0e98c854c09a7c93d3d944336b0eb2a1594689c2`；
- 交互式火焰图：当前 Codex 任务 visualization 目录中的 `lkrequest-hpack-self-flamegraph.html`。

