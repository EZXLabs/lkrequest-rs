# Linux HTTP/2 性能测试报告（2026-09-05）

本文记录 `codex/h2-performance-bench` 在独立 Linux 主机上的 h2c 性能验证。所有正式数字均来自修正 benchmark server `TCP_NODELAY` 之后的五轮交替顺序测试；修正前的数据只用于诊断，不进入本报告。

## 测试范围

- 关注连接复用、HTTP/2 multiplexing、Session 拆分、runtime worker 和 1 MiB 下载吞吐；
- 比较 `lkrequest 0.2.1`、`hyper 1.11.1` 和 `reqwest 0.13.4`；
- `lkrequest-batch64` 是启用 `h2_dispatch_batch_size(64)` 的 A/B 变体；
- 所有客户端和 benchmark server 均启用 `TCP_NODELAY=true`；
- 本轮不测试 TLS、HTTP/2 或 HTTP/3 指纹，也不据此声明浏览器线缆一致性。

## 环境与方法

- Ubuntu 24.04.4 LTS，kernel `6.8.0-117-generic`；
- KVM 虚拟机，28 个 QEMU vCPU，2 个 NUMA node；
- Rust `1.89.0-nightly (f3db63916 2025-06-17)`，release 构建；
- loopback h2c，响应 body 为 1 KiB 或 1 MiB，响应体完整消费并校验长度；
- 每个 Session 先完成 200 次预热，正式测量运行 5 轮，偶数轮反转客户端顺序；
- 单 worker：客户端固定 CPU 1，服务端固定 CPU 2-3；
- 四 worker：客户端固定 CPU 1-4，服务端固定 CPU 5-8；
- 表格使用五轮中位数，所有正式轮次均为 0 failures，连接数符合场景配置。

该主机是共享内核调度下的 KVM 虚拟机，不是裸机。结果适合定位实现差异和验证优化方向，不应作为跨机器的绝对性能排名。

## 正确性验证

- `cargo test --workspace --lib --tests`：所有 library 和 test target 通过；
- `cargo test -p lkh2`：237 个单元测试和 1 个 doctest 通过；
- `cargo test -p lkrequest h2_dispatch_batch -- --nocapture`：3 个匹配测试通过；
- `cargo test -p http-client-bench`：4 个测试通过；
- `cargo build --release -p http-client-bench`：通过。

`cargo test --workspace` 在干净源码快照中会编译 example，并因 `lkrequest/examples/peet_ws_baseline_match.rs` 使用 `include_str!` 引用未跟踪的 `tlsleak/peet_baseline_chrome_148.json` 而失败。这是现有仓库的干净 checkout 可构建性问题，不是性能改动造成的测试失败。

当前 nightly 上，全 workspace `clippy -D warnings` 还会被既有的 `clippy::uninlined_format_args` 警告阻断。针对本次涉及的 `lkh2`、`lkrequest`、`http-client-bench`，使用 `--no-deps -D warnings -A clippy::uninlined-format-args` 后通过，确认没有其他 lint 问题。

## 单 Worker 标准矩阵

吞吐单位为 req/s；1 MiB 场景的数值也等于 MiB/s。

| 场景 | lkrequest | Batch64 | Hyper | reqwest |
|---|---:|---:|---:|---:|
| 顺序复用，1 KiB，c1 | 4,534 | 4,361 | 5,534 | 4,762 |
| 单连接，1 KiB，c8 | 11,183 | 12,772 | 28,821 | 23,280 |
| 单连接，1 KiB，c32 | 11,597 | 14,067 | 33,392 | 34,076 |
| 单连接，1 KiB，c128 | 12,196 | 16,558 | 39,845 | 40,286 |
| 单连接，1 MiB，c32 | 869 | 1,290 | 851 | 876 |

对应 p99：

| 场景 | lkrequest | Batch64 | Hyper | reqwest |
|---|---:|---:|---:|---:|
| 顺序复用，1 KiB，c1 | 298 us | 281 us | 245 us | 266 us |
| 单连接，1 KiB，c8 | 1,109 us | 983 us | 510 us | 566 us |
| 单连接，1 KiB，c32 | 4,132 us | 3,236 us | 1,443 us | 1,269 us |
| 单连接，1 KiB，c128 | 13,179 us | 12,803 us | 5,486 us | 5,269 us |
| 单连接，1 MiB，c32 | 51,598 us | 44,646 us | 49,983 us | 48,620 us |

结论：

- 修正服务端 socket 后没有再次出现约 41 ms 的固定 p99 断崖，之前的异常是 benchmark server 保留 Nagle 导致的测量污染；
- 默认 lkrequest 在 c32 只有 reqwest 吞吐的 34.0%，Batch64 提高到 41.3%，仍存在明显的编码、调度和响应路径开销；
- Batch64 相对默认在 c8、c32、c128 分别提升 14.2%、21.3%、35.8%；并发越高，单连接一次可收集的 ready 请求越多；
- 顺序场景没有收益，说明 batching 不是无条件加速；
- 1 MiB 场景 Batch64 中位吞吐提升 48.5%，但 KVM loopback 和仅 500 请求使该场景波动高于小响应矩阵，应在裸机和真实 TLS 链路继续验证。

## 多 Session 与 Runtime Worker

总并发固定为 32：

| Client workers | Sessions | Default req/s | Batch64 req/s | 变化 | Default p99 | Batch64 p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 11,597 | 14,067 | +21.3% | 4,132 us | 3,236 us |
| 1 | 4 | 11,743 | 13,975 | +19.0% | 4,520 us | 3,565 us |
| 1 | 8 | 11,515 | 12,509 | +8.6% | 4,699 us | 3,955 us |
| 1 | 32 | 9,885 | 9,797 | -0.9% | 3,936 us | 4,021 us |
| 4 | 1 | 11,854 | 14,706 | +24.1% | 3,636 us | 3,163 us |
| 4 | 4 | 26,822 | 25,368 | -5.4% | 2,197 us | 2,275 us |
| 4 | 8 | 24,673 | 24,348 | -1.3% | 2,488 us | 2,333 us |
| 4 | 32 | 27,684 | 26,244 | -5.2% | 2,020 us | 2,140 us |

这说明 batching 的收益属于“单条繁忙 H2 连接”的局部优化。多 Session 将总并发拆散到多条连接后，每条连接没有足够多的 ready 请求可合并；四 worker 已能让多条连接并行推进，此时 Batch64 不再改善吞吐，约 1%–5% 的差异应视为无收益或轻微成本，而不是继续默认扩大 batch。

## 系统调用证据

在单 worker、单连接、20,000 请求、并发 32 下使用 `strace -f -c`：

| 模式 | `sendto` calls | `recvfrom` calls | 网络相关 syscall 时间 |
|---|---:|---:|---:|
| Default | 20,204 | 2,216 | 0.2096 s |
| Batch64 | 2,269 | 3,100 | 0.0217 s |

Batch64 将发送调用减少 88.8%，约为默认的 1/8.9。该结果与 Windows 抓包中 payload packet 大幅减少的方向一致，直接支持“性能提升主要来自合并小 write”的判断。

`perf` 因主机 `perf_event_paranoid=4` 且无免密 sudo 不可用。`dumpcap` 虽带 capabilities，但权限为 `root:wireshark 0754`，测试用户不在 `wireshark` 组，因此无法执行。本次没有使用 host-network + `NET_ADMIN` 容器绕过主机权限；Linux 报告不包含新的 packet capture，保留 Windows 抓包作为现有旁证。

## 最终判断

1. `TCP_NODELAY` 必须在 benchmark 两端匹配；否则 Nagle/delayed ACK 会制造与客户端实现无关的尾延迟断崖。
2. H2 write batching 的作用路径已经由吞吐、p99 和 `sendto` 数量共同确认。
3. Batch64 适合少量高并发复用连接，不适合无条件作为浏览器 preset 或所有多 Session 负载的默认值。
4. 即使开启 Batch64，lkrequest 的单连接小响应吞吐仍显著低于 Hyper/reqwest，后续应继续分析 HPACK/帧编码、command channel、响应事件分发和每请求分配。
5. 多 Session 真实环境应优先增加合理的 runtime worker 并分散连接，而不是单纯提高每连接 batch size。

默认配置的 CPU 采样进一步确认，第一瓶颈是 `fluke-hpack` 为每个 Huffman 字符串重新构造 decoder HashMap，inclusive CPU 占比达到 44.34%；socket `send` 为第二个明确热点，占 17.04%。完整分析见 [默认配置 CPU 火焰图分析](FLAMEGRAPH-DEFAULT-2026-09-05.md)。

## 原始数据

- 本地目录：`benchmark-results/linux-2026-09-05/`，已由 `.gitignore` 排除；
- 归档：`linux-final-results.tar.gz`；
- SHA-256：`dd37c15436b70ea0210a50e16af9bc8973a915b3b1c95011a93b8342a6752a9c`；
- `postfix-pinned-w1/` 和 `postfix-pinned-w4/` 保存全部 JSON、环境、服务端日志和生成的摘要；
- `profiling/` 保存 `strace` 原始输出和抓包权限失败记录。
