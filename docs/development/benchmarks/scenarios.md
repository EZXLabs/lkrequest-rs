# 标准 benchmark 场景

本页定义后续可重复运行的最小性能矩阵。场景名称、请求数和连接模型应保持稳定；变更定义时要创建新场景 ID，不能覆盖历史语义。

## H2 请求级矩阵

| 场景 ID | 响应体 | 请求数 | 并发 | 连接模型 | 主要观察项 |
|---|---:|---:|---:|---|---|
| `sequential-1k-c1` | 1 KiB | 20,000 | 1 | 单 Session、单连接复用 | 固定开销、顺序延迟 |
| `multiplex-1k-c8` | 1 KiB | 30,000 | 8 | 单 Session、单 H2 连接 | 低并发 multiplexing |
| `multiplex-1k-c32` | 1 KiB | 50,000 | 32 | 单 Session、单 H2 连接 | 调度与编码吞吐 |
| `multiplex-1k-c128` | 1 KiB | 50,000 | 128 | 单 Session、单 H2 连接 | 高并发排队与尾延迟 |
| `download-1m-c32` | 1 MiB | 1,000 | 32 | 单 Session、单 H2 连接 | 大 body 吞吐与内存 |

每个场景至少记录吞吐、p50/p95/p99、失败数、实际连接数、CPU 时间和 peak RSS。响应体必须完整消费并校验长度。

## Session 与 runtime 维度

标准 H2 矩阵之外，应单独扫描：

- 总并发固定为 32，Session 数取 1、4、8、32；
- runtime worker 数取 1 和 4；
- 明确每个 Session 是否形成独立连接；
- 对比默认配置与待验证的 opt-in 参数；
- 不把多连接扩展结果混入单连接 multiplexing 排名。

## 独立场景

下列成本需要单独建模，不能混入 h2c loopback 基线：

| 类别 | 必须说明的条件 |
|---|---|
| Fresh TLS | TLS 版本、session resumption、证书链、DNS 是否计时 |
| Reused TLS/H2 | 连接预热、连接寿命、每连接 request 上限 |
| H3/QUIC | 0-RTT、Alt-Svc/SVCB 发现、UDP 路径、fallback、QUIC backend |
| Proxy | HTTP CONNECT/SOCKS5、远端 DNS、代理 RTT、连接复用边界 |
| Public network | 目标、地区、时间窗口、失败和限流；默认不得进入 CI |
| CLI cold start | 进程启动到退出，可使用 Hyperfine；不得冒充请求级延迟 |
| Fingerprint | 抓包与字段 diff；不以 req/s 判断 wire parity |

## 运行顺序

每轮先完成预热，再以交替或随机顺序运行所有客户端。原始数据应逐轮写入 JSONL，并包含场景 ID、实现、revision、开始时间、环境摘要和所有指标；Markdown 表格仅作为可读派生结果。

