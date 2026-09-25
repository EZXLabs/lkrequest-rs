# 默认配置 CPU 火焰图分析（2026-09-05）

## 测试配置

- 客户端：默认 `lkrequest`，未开启 H2 write batching；
- 协议：loopback h2c prior knowledge；
- 负载：单 Session、单 H2 连接、1 KiB 响应、并发 32；
- runtime：客户端 1 worker，服务端 2 workers，固定在同一 NUMA node；
- profiler：`gprofng collect app -p 10 -t 15s`，release binary 保留 debuginfo；
- 采样得到 14.14 秒 attributed CPU time，测试期间吞吐约 11.9k req/s；
- 本轮只分析 CPU 性能，不测试指纹。

服务器的 `perf_event_paranoid=4` 禁止普通用户运行 `perf`。GDB 周期停顿采样受该环境的 inferior 信号处理限制，因此最终采用无需 root 的 gprofng 时钟采样。Ubuntu 自带 `gp-display-html` 因 `bigint::hex` 兼容错误无法完成 HTML 输出，火焰图根据 gprofng attributed call tree 在本地生成。

## 主要热点

以下为 inclusive CPU time，同一路径中的父子项会重叠，不能直接相加：

| 调用路径 | CPU time | 总 CPU 占比 | 判断 |
|---|---:|---:|---|
| `lkh2::driver::driver_loop` | 10.16 s | 71.85% | 主要 CPU 集中在单连接 driver |
| `H2Engine::process` | 6.83 s | 48.30% | 响应帧和响应头处理是最大分支 |
| `HuffmanDecoder::new` | 6.27 s | 44.34% | 最大单项瓶颈，反复构造解码表 |
| `HashMap::insert`，位于 decoder 构造 | 3.38 s | 23.90% | 建表产生大量 hash/rehash |
| socket `send` | 2.41 s | 17.04% | 默认模式每请求小 write 的成本 |
| benchmark/request task 分支 | 3.51 s | 24.82% | 高层请求、future、响应转换开销 |
| `send_with_redirects` | 2.78 s | 19.66% | 请求 pipeline 仍有明显成本 |
| `send_h2_request` | 1.70 s | 12.02% | pool、oneshot、请求/响应适配开销 |

## 第一瓶颈：HPACK Huffman Decoder 重建

`fluke-hpack 0.3.1` 的 `decode_string` 在遇到每个 Huffman 编码字符串时执行：

```rust
let mut decoder = HuffmanDecoder::new();
let decoded = decoder.decode(raw_string)?;
```

`HuffmanDecoder::new()` 又遍历 HPACK 的 257 项静态码表，并为每个 decoder 构造嵌套 `HashMap<u8, HashMap<u32, HuffmanCodeSymbol>>`。因此短响应头的实际字符解码只占很小部分，绝大多数 CPU 被建表、hash、rehash、分配和释放消耗。

这是本次 profile 中最明确、优先级最高的根因。适合的修复方向是让 decoder table 在连接级或进程级复用，或者改为预生成的只读数组/trie，而不是每个 header string 重新构造 HashMap。

该优化只改变本地响应解码实现，不改变客户端发送的 TLS ClientHello、H2 SETTINGS、HPACK 请求编码或 frame 顺序，理论上不影响请求侧指纹；仍应通过现有回归测试确认行为一致。

## 第二瓶颈：默认模式的小 Write

`dispatch_waiting_requests -> encode_and_write_frames -> write_all -> send` 占 2.41 秒，即 17.04%。这与此前 `strace` 一致：20,000 请求中，默认模式执行 20,204 次 `sendto`，Batch64 只有 2,269 次。

H2 write batching 已能缓解该分支，但默认保持关闭是为了保留 write/TLS record/TCP segmentation 边界。应先修复 HPACK decoder 重建，因为它占比更高，且对请求侧线缆行为风险更低。

## 建议顺序

1. 为 `fluke-hpack` Huffman decoder table 增加复用或替换为静态查找结构；
2. 对比默认版本的 c8/c32/c128、CPU time 和 p99，确认 44% 热点消失；
3. 重新生成火焰图，检查热点是否转移到 socket write 或请求 pipeline；
4. 再评估默认 batching 策略，不把两项优化混在同一次 A/B 中；
5. 最后分析 `send_with_redirects`、response adapter、oneshot/channel 和每请求分配。

## 原始文件

- `benchmark-results/linux-2026-09-05/gprofng-functions.txt`；
- `benchmark-results/linux-2026-09-05/gprofng-calltree.txt`；
- `benchmark-results/linux-2026-09-05/gprofng-default-c32.json`；
- 交互式火焰图保存在当前 Codex 任务的 visualization 目录。

