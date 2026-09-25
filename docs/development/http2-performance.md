# HTTP/2 性能修复与验证计划

本文汇总 lkrequest HTTP/2 客户端的性能问题、已经完成的修复、当前 A/B 证据，以及后续在独立 Linux 服务器上的复测方案。

## 状态与范围

- 当前实现和初步 A/B 完成于 2026-09-05；
- 已有数据来自 Windows loopback h2c，仅用于定位实现瓶颈和验证优化方向；
- 当前数据不是跨平台发布基准，也不能代替真实 HTTPS、代理链路或公网测试；
- 本轮性能测试不评价 TLS/H2/H3 指纹相似度；
- 任何可能改变线缆行为的优化仍必须保持显式、可关闭，并单独进行指纹验证。

## 修复摘要

| 项目 | 原始问题 | 当前处理 | 默认行为 |
|---|---|---|---|
| TCP 小包延迟 | 默认连接可能保留 Nagle，与 delayed ACK 共同产生 10–25 ms 尾延迟 | 新建 TCP 连接默认设置 `TCP_NODELAY=true` | 默认启用，可被 TCP fingerprint 显式覆盖 |
| Benchmark server TCP 行为 | accepted socket 的 Nagle 可能污染 Linux 尾延迟 | server 与所有客户端统一设置 `TCP_NODELAY=true` | benchmark 固定启用 |
| H2 请求写入 | 每个 ready 请求单独编码、`write_all` 和 flush，产生大量小 write | 支持有界地收集 ready 请求并合并写入 | 默认关闭，batch size 为 `1` |
| HPACK 响应解码 | `fluke-hpack` 为每个 Huffman 字符串重建嵌套 `HashMap` | 使用 `lkh2` 自研 HPACK decoder 和进程级只读 Huffman trie | 默认且唯一的生产解码路径 |
| 多 Session 行为 | 单连接结果不能代表大量独立 Session | benchmark 支持 `--sessions`，按 Session 建立独立连接 | 显式设置测试拓扑 |
| 可复现性 | 单次结果容易受顺序、预热和环境影响 | 固定 workload、预热、交替客户端顺序、保留 JSON 和分位数 | 标准矩阵运行三轮以上 |

## 修复一：默认启用 TCP_NODELAY

### 问题

初始 benchmark 中，Hyper、reqwest 和直接 lkh2 客户端均使用 `TCP_NODELAY=true`，而未配置 TCP fingerprint 的 lkrequest 保留了 Nagle。大量小型 H2 HEADERS、DATA 和控制帧与 delayed ACK 组合后，形成了明显的 p99 延迟断崖。

这使最初的客户端对比并不公平：它同时比较了 HTTP 客户端实现和不同的 TCP socket 行为。

### 修复

TCP 连接建立后先设置：

```rust,ignore
socket.set_tcp_nodelay(true)?;
```

随后再应用可选的 `TcpFingerprint`。因此显式配置 `tcp_nodelay=false` 仍能覆盖默认值，保留研究特殊网络栈行为的能力。

实现位置：[`lkrequest/src/tcp_fingerprint.rs`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkrequest/src/tcp_fingerprint.rs)。

### 初步效果

在 Windows loopback、单 H2 连接、并发 32 的 A/B 中，只改变 `TCP_NODELAY`：

- 吞吐从约 19–24k req/s 提升到约 30–34k req/s；
- p99 从约 16–17 ms 降低到约 2.7–4.2 ms；
- 原有 10–25 ms 级异常等待基本消失。

详细定位过程见 [HTTP/2 性能差异诊断](https://github.com/EZXLabs/lkrequest-rs/blob/main/tools/http-client-bench/DIAGNOSIS-2026-09-05.md)。

## 修复二：可选 H2 Write Batching

### 剩余瓶颈

修正 TCP 行为后，小响应高并发场景仍明显落后。20,000 个请求、并发 32 的 loopback 抓包显示：

| 客户端 | 客户端到服务端 payload packets | 平均 payload | packets/request |
|---|---:|---:|---:|
| lkrequest | 20,132 | 21.1 bytes | 1.007 |
| direct lkh2 | 19,849 | 20.4 bytes | 0.992 |
| Hyper | 2,149 | 141.1 bytes | 0.107 |
| reqwest | 1,570 | 193.2 bytes | 0.078 |

lkrequest/lkh2 基本每个请求产生一个很小的 TCP payload，而 Hyper 和 reqwest 会把多个请求的 frame 聚合到较少的 write 中。

### 实现

H2 driver 新增三个有界参数：

- `max_ready_commands_per_turn`：单轮最多收集多少个已经 ready 的请求命令；
- `max_requests_per_write`：一次底层 write 最多合并多少个请求；
- `max_write_batch_bytes`：累计输出缓冲区的字节上限，当前默认 64 KiB。

高层 API 将命令收集和写入请求数统一暴露为：

```rust,ignore
let client = Client::builder()
    .h2_dispatch_batch_size(64)
    .build();
```

默认值仍为 `1`。只有显式设置大于 `1` 时，driver 才会收集并合并多个 ready 请求。实现保持 request、stream 和 frame 顺序，不改变 SETTINGS、HPACK、伪头顺序或 frame 字节。

实现位置：

- [`lkh2/src/driver.rs`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkh2/src/driver.rs)
- [`lkrequest/src/client.rs`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkrequest/src/client.rs)

### 单 Session A/B

Windows loopback h2c、1 KiB 响应、一个 client runtime worker、两个 server runtime workers、复用一条 H2 连接：

| 并发 | 模式 | 中位吞吐 | 中位 p99 | 变化 |
|---:|---|---:|---:|---:|
| 1 | default | 18,980 req/s | 110 us | baseline |
| 1 | batch64 | 19,125 req/s | 104 us | +0.8% |
| 32 | default | 33,418 req/s | 1,401 us | baseline |
| 32 | batch64 | 46,973 req/s | 977 us | +40.6% |

低并发基本没有退化；高复用连接上的并发请求能够明显受益。

### 多 Session A/B

总并发固定为 32，每行取三轮交替顺序测试的中位数：

| Sessions | 每 Session 并发 | Default req/s | Batch64 req/s | 吞吐变化 | Default p99 | Batch64 p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 32 | 33,997 | 46,891 | +37.9% | 1,395 us | 987 us |
| 4 | 8 | 35,104 | 41,132 | +17.2% | 1,674 us | 1,302 us |
| 8 | 4 | 34,681 | 37,499 | +8.1% | 1,764 us | 1,621 us |
| 32 | 1 | 30,280 | 30,511 | +0.8% | 2,827 us | 2,803 us |

batching 在每条 H2 连接内部工作。总并发被拆分到更多独立 Session 和连接后，每条连接可同时收集的 ready 请求减少，收益也随之下降。

### 写入合并证据

单连接、20,000 请求、并发 32：

| 模式 | 客户端到服务端 payload packets | 平均 payload | packets/request |
|---|---:|---:|---:|
| default | 20,954 | 21.1 bytes | 1.05 |
| batch64 | 2,610 | 169.0 bytes | 0.13 |

两次抓包传输了相同的 441,147 TCP payload bytes。Batch64 将 payload packet 数量降低了 87.5%，说明吞吐收益来自减少小 write，而不是跳过请求处理。

完整 A/B 见 [HTTP/2 dispatch batching A/B](https://github.com/EZXLabs/lkrequest-rs/blob/main/tools/http-client-bench/AB-BATCHING-2026-09-05.md)。

## 修正后的主流客户端对比

修正 `TCP_NODELAY` 后，Windows loopback h2c 的三轮中位结果如下：

| 场景 | lkrequest | Hyper | reqwest |
|---|---:|---:|---:|
| 顺序复用，1 KiB | 18,715 req/s | 27,891 req/s | 24,440 req/s |
| 并发 8，1 KiB | 31,715 req/s | 54,865 req/s | 66,945 req/s |
| 并发 32，1 KiB | 34,449 req/s | 167,007 req/s | 108,726 req/s |
| 并发 128，1 KiB | 34,577 req/s | 156,179 req/s | 120,200 req/s |
| 并发 32，1 MiB | 844 MiB/s | 810 MiB/s | 833 MiB/s |

这些结果说明：

- 异常的毫秒级等待已经修复；
- 大 body 吞吐已经与主流客户端接近；
- 小请求、高 multiplexing 场景仍存在 CPU、调度和写入路径差距；
- Batch64 能缩小差距，但 Windows loopback 数字不能直接外推到 Linux 或真实网络。

## 指纹边界

`TCP_NODELAY` 和 write batching 都不改变 TLS ClientHello、H2 SETTINGS、HPACK 或 frame 字节，但可能改变 TLS record 边界、TCP segment 分布、请求 burst 和响应时序。

因此：

- `TCP_NODELAY=true` 作为交互式 HTTP 客户端默认值，但允许 fingerprint 显式覆盖；
- H2 batching 默认保持 `1`，性能模式必须显式启用；
- h2c 性能测试不能证明 HTTPS 下的 TLS record 行为与 Chrome 一致；
- 将 batching 绑定到浏览器 preset 前，必须完成真实浏览器 HTTPS 抓包验证。

详细边界见 [HTTP/2 Write Batching：性能与指纹边界](h2-write-batching.md)。

## 修复三：自研 HPACK 解码器

### 问题

原响应路径依赖 `fluke-hpack 0.3.1`。它虽然在连接级保存 HPACK 动态表，但每解码一个 Huffman 字符串都会重新创建 decoder，并遍历 RFC 7541 的 257 项码表构造嵌套 `HashMap`。Linux CPU profile 中，`HuffmanDecoder::new` 的 inclusive CPU 占比达到 44.34%，其中大量时间消耗在 `HashMap::insert`、分配和释放，而不是真正的字符解码。

### 实现

`lkh2` 现在自行实现完整的生产 HPACK 编解码路径：

- 编码器继续负责浏览器策略控制、静态表、动态表、整数编码和 Huffman 编码；
- 新解码器支持 indexed、incremental indexing、without indexing、never indexed 和 dynamic table size update；
- 编解码器共享同一份 RFC 7541 静态表和动态表实现；
- Huffman 解码 trie 从固定码表进程级初始化一次，所有连接只进行数组节点遍历；
- 校验非法索引、整数溢出、截断字符串、EOS、非法 padding、非法 table size update 位置和大小；
- `fluke-hpack` 已从生产和开发依赖中完全移除。

正确性验证不只依赖“自编码再自解码”闭环，而是同时采用 RFC 7541 C.4/C.6 完整状态序列、`h2` 的独立 Huffman 已知字节向量，以及对 `h2` 服务端的端到端互操作测试。生产代码不调用参考实现。

实现位置：

- [`lkh2/src/hpack_enc/decoder.rs`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkh2/src/hpack_enc/decoder.rs)
- [`lkh2/src/hpack_enc/huffman.rs`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkh2/src/hpack_enc/huffman.rs)
- [`lkh2/src/hpack_enc/table.rs`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkh2/src/hpack_enc/table.rs)

### Windows loopback A/B

2026-09-05 使用修改前已构建的同分支二进制作为基线，与自研版本交替运行三轮。场景固定为 h2c、1 KiB 响应、50,000 请求、并发 32、单 Session、单 runtime worker；两者复用同一条 H2 连接，所有轮次均为 0 failures。

| 实现 | 三轮吞吐 | 中位吞吐 | 中位 p99 | 相对旧实现 |
|---|---:|---:|---:|---:|
| `fluke-hpack` decoder | 35,275 / 35,689 / 36,133 req/s | 35,689 req/s | 1,431 us | baseline |
| `lkh2` decoder | 59,369 / 60,116 / 61,169 req/s | 60,116 req/s | 992 us | **+68.4%** |

同机三轮主流客户端对比中位数：

| 客户端 | 中位吞吐 | 中位 p99 | lkrequest 相对值 |
|---|---:|---:|---:|
| lkrequest 自研 HPACK | 62,400 req/s | 856 us | 100% |
| Hyper 1.11.1 | 105,827 req/s | 685 us | 59.0% |
| reqwest 0.13.4 | 100,241 req/s | 778 us | 62.3% |

这说明 HPACK decoder 重建是先前最大的 CPU 根因，但不是全部差距。该修改只影响接收端解码，不改变请求 HPACK 编码、HEADERS 字节、frame 顺序、TLS record 或 TCP write 行为，因此不改变请求侧指纹。

### Linux 重新采样

在与旧火焰图完全相同的单连接 c32 负载下重新采样后，吞吐从 11,023 提升到 20,016 req/s（+81.6%），p99 从 4,153 降至 1,850 us（-55.5%），进程 CPU/request 下降 45.7%。`HuffmanDecoder::new` 的 44.34% 热点完全消失，`HeaderDecoder::decode` 降至 3.21%，其中实际 `huffman::decode` 仅占 0.20%。

当前最大热点转移为 socket `send` 31.42% 和 `encode_and_write_frames` 33.69%；其次是高层 `send_with_redirects`、`send_h2_request`、oneshot/request state 与 response adapter。这与 write batching 的 syscall A/B 证据一致。完整调用树、对比表和原始归档哈希见 [自研 HPACK 替换后 CPU 火焰图](https://github.com/EZXLabs/lkrequest-rs/blob/main/tools/http-client-bench/FLAMEGRAPH-HPACK-SELF-2026-09-05.md)。

## 修复四：原生请求与响应头单次解析

普通 H2 请求此前先构造 `http::Request<()>`，随后 adapter 再把 `HeaderName/HeaderValue` 转为拥有的 `String` pair，body 也通过额外 oneshot channel 交给 response future。现在 `RequestBuilder::send()` 直接构造 `NativeH2Request`，有序 header 保留为 typed header，body 直接随 native request 进入 driver。

响应路径此前在 driver 中验证一次字段，随后在 response adapter 中再次验证、解析 `HeaderName/HeaderValue` 并逐项插入。现在 driver 在验证时直接生成最终 `HeaderMap`，上层只设置 status、headers 和 body，不再重复解析。

该修改不改变请求 header order、pseudo-header order、HPACK 编码、frame 内容或 write grouping。新增字节级回归使用旧入口和新入口分别编码包含重复 cookie 与 body 的请求，并断言完整 frame bytes 相等；响应测试同时覆盖重复 `set-cookie` 的保留。

Ubuntu 单连接 c32 七轮交替 A/B 中，中位吞吐从 21,453 提升至 23,417 req/s（**+9.2%**），CPU/request 从 46.61 降至 42.66 us（**-8.5%**），p50/p95/p99 分别改善 9.3%/4.6%/1.8%。完整轮次和原始归档哈希见 [H2 原生请求与响应头单次解析 A/B](https://github.com/EZXLabs/lkrequest-rs/blob/main/tools/http-client-bench/AB-NATIVE-HEADERS-2026-09-05.md)。

## Benchmark 工具

性能 harness 位于 [`tools/http-client-bench`](https://github.com/EZXLabs/lkrequest-rs/blob/main/tools/http-client-bench/README.md)，支持主流客户端、底层诊断变体、独立 server/client 进程、预热、连接复用、多 Session、JSON 原始结果、延迟分位数、CPU、RSS 和连接 ID。

Hyperfine 只适合测量进程启动或完整 CLI 生命周期，不作为复用连接下请求级延迟的主要数据源。

## Linux 验证结果

2026-09-05 已在 Ubuntu 24.04 KVM 主机完成修正 benchmark server `TCP_NODELAY` 后的五轮正式矩阵。完整环境、表格、系统调用证据和原始数据哈希见 [Linux HTTP/2 性能测试报告](https://github.com/EZXLabs/lkrequest-rs/blob/main/tools/http-client-bench/LINUX-RESULTS-2026-09-05.md)。

关键结论：

- 单 worker、单连接、1 KiB、并发 32：默认为 11,597 req/s，Batch64 为 14,067 req/s，Hyper 为 33,392 req/s，reqwest 为 34,076 req/s；
- Batch64 在单连接 c8/c32/c128 分别提升 14.2%/21.3%/35.8%，但四 worker 的 4–32 Session 场景没有吞吐收益；
- `strace` 中 `sendto` 从 20,204 次降至 2,269 次，减少 88.8%，确认优化来自合并小 write；
- 修正服务端 accepted socket 后，Linux 上约 41 ms 的 p99 断崖消失，证明旧结果是 server Nagle 污染；
- Linux 主机禁止普通用户运行 `perf` 和 `dumpcap`，因此报告保留限制，不使用高权限容器绕过；
- 本轮只评价性能，不评价指纹。

## Linux 服务器复测方法

以下流程用于复现或在裸机上继续验证。Linux 结果应单独保存，不覆盖 2026-09-05 的 Windows 原始报告。

### 1. 固定和记录环境

```bash
date --iso-8601=seconds
uname -a
lscpu
nproc
rustc -Vv
cargo -V
git rev-parse HEAD
git submodule status
```

同时记录 Linux 发行版、kernel、CPU/NUMA、CPU governor、turbo、内存、虚拟化或容器、cgroup 限制、loopback/offload 配置和其他高负载进程。

### 2. 准备源码与测试

```bash
git submodule update --init --recursive
cargo build --release -p http-client-bench
cargo test -p lkh2
cargo test -p lkrequest h2_dispatch_batch
cargo test -p http-client-bench
```

### 3. 标准客户端矩阵

至少运行五轮，并固定 runtime worker 数量：

```bash
ROUNDS=5 \
CLIENT_RUNTIME_WORKERS=1 \
SERVER_RUNTIME_WORKERS=2 \
RESULTS_DIR=benchmark-results/linux-h2-client-w1 \
./tools/http-client-bench/scripts/run-matrix.sh
```

随后使用与 CPU 核数匹配的多线程配置复测，例如：

```bash
ROUNDS=5 \
CLIENT_RUNTIME_WORKERS=4 \
SERVER_RUNTIME_WORKERS=4 \
RESULTS_DIR=benchmark-results/linux-h2-client-w4 \
./tools/http-client-bench/scripts/run-matrix.sh
```

必须保留每轮 JSON、`environment.txt`、`summary.json`、`SUMMARY.md` 和 server 日志。

### 4. Batching 与多 Session 矩阵

固定总并发，至少比较：

- default 与 `lkrequest-batch64`；
- concurrency 1、8、32、128；
- Sessions 1、4、8、32；
- 1 KiB 小响应和 1 MiB 大响应；
- 单 worker 与多 worker runtime。

### 5. Linux 性能剖析

对稳定复现的场景使用：

- `perf stat`：cycles、instructions、IPC、context switches 和 migrations；
- `perf record` / flamegraph：driver、channel、HPACK、buffer 和 runtime 热点；
- `strace -f -c`：write/writev/sendmsg 等 syscall 数量；
- `tcpdump` / Wireshark：payload packet、segment size 和 burst；
- 必要时固定 CPU affinity，区分 scheduler 抖动和实现开销。

### 6. 结果判定

Linux 报告至少回答：

1. `TCP_NODELAY` 修复是否仍能消除尾延迟断崖；
2. 默认 lkrequest 与 Hyper/reqwest 的小请求差距有多大；
3. Batch64 在单连接高并发下的真实收益和 CPU 成本；
4. 多 Session 后收益下降曲线是否与 Windows 一致；
5. 大 body 是否继续保持相近吞吐；
6. 单线程瓶颈主要位于 syscall、runtime 调度、channel、HPACK 还是响应分发；
7. 不同轮次的波动是否足够小，可以形成可发布结论。

最终报告应优先使用中位数，并同时给出 p50、p95、p99、CPU、RSS、连接数和轮间离散程度。任何异常结果都应保留原始 JSON 和系统环境，而不是只保留汇总表。
