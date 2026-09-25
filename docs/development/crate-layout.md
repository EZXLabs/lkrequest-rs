# 架构与 crate 边界

lkrequest 将高层会话状态、协议实现和线缆指纹控制分层隔离。修改应落在能够完整表达需求的最高层；只有确实需要改变序列化字节或传输行为时，才进入底层协议 crate。

本页面向贡献者，说明源码结构、设计不变量和修改归属。应用开发者应从[使用场景导航](../guides/README.md)开始；只需要判断 Client 与 Session 生命周期时，阅读[用户对象模型](../guides/object-model.md)。

## Workspace 分层

```text
lkrequest-ffi ──► lkrequest
                     │
        ┌────────────┼────────────┐───────────┐
        ▼            ▼            ▼           ▼
      lktls        lkh2         lkh3        lkquic
        │                        │           │
        └────────► lktls-quic ◄──┘           │
                                  deps/h3 ◄──┤
                                deps/quinn ◄─┘
```

- `lkrequest` 负责用户可见的 Client、Session、请求策略和传输选择。
- `lktls`、`lkh2` 和 `lkh3` 负责协议编码以及 fingerprint-sensitive 行为。
- `lkquic` 管理 QUIC endpoint 和 backend；`lktls-quic` 提供 QUIC TLS bridge。
- `lkmasque` 负责 MASQUE CONNECT-UDP 的线上格式与 Sans-I/O 隧道状态机（`masque` feature 可选引入）；把状态机驱动到 patched `h3`/`quinn` 上的 I/O 桥接留在 `lkrequest` 内（`proxy::masque`），因为它只能针对这两个 fork 编译。
- `lkrequest-ffi` 只暴露稳定 C ABI，不复制高层业务逻辑。
- `deps/h3` 与 `deps/quinn` 是带本地补丁的 submodule；非上游补丁工作不应直接修改它们。

## 高层对象模型

### Client

`Client` 是不可变、可共享的指纹模板，包含 TLS/H2/H3 profile、默认 headers、超时和资源限制。相同浏览器指纹下可以复用并廉价 clone。

### Session

`Session` 表示一个虚拟浏览器用户，拥有独立的 Cookie、连接池、代理配置、HSTS、Alt-Svc 和 QUIC fallback 状态。不同 Session 不共享连接。

### Pool

`ProxyPool` 管理代理选择和并发预算；`SessionPool` 在其上管理 Session 生命周期与轮换。连接上限应约束物理连接，而不是仅限制逻辑请求数量。

## 请求生命周期

一次请求依次经过：

1. request builder 组装 method、headers、body 和单次请求选项；
2. middleware、retry 和 redirect 策略；
3. transport 根据显式策略、Alt-Svc 与 QUIC 失败状态选择 H1/H2/H3；
4. DNS、TCP/UDP、代理、TLS 和协议握手；
5. connection pool 复用连接并执行 multiplexing；
6. response 层处理 streaming、解压和资源释放。

状态应由拥有其生命周期的层维护。例如 Cookie 与 HSTS 属于 Session，TLS 扩展顺序属于 `lktls` profile，H2 SETTINGS 属于 `lkh2` profile，QUIC transport parameters 属于 H3/QUIC profile。

## 高层模块职责

| 模块 | 职责 | 不应承担 |
|---|---|---|
| `client` / `preset` | 共享配置、跨协议 preset、默认策略 | 每个身份的 Cookie 或连接 |
| `session` | 请求 pipeline、身份状态和 protocol selection | TLS/H2/H3 字节序列化细节 |
| `connection_pool` | 按 origin、proxy 和协议复用物理连接 | 代理轮换或 Session 生命周期 |
| `proxy` | HTTP CONNECT、SOCKS5、chain 和 UDP relay | 业务 retry 决策 |
| `proxy_pool` / `session_pool` | 并发 permit、rotation、cooldown 和 guard | 单连接 stream flow control |
| `dns` | resolver、cache、HTTPS/SVCB 和 ECH config discovery | Alt-Svc response cache |
| `alt_svc` / `protocol` | H3 advertisement、acquisition 和 fallback policy | QUIC packet encoding |
| `middleware` / `retry` | 请求包装、重放策略和 backoff | 判断底层 frame 是否匹配浏览器 |
| `response` / `session::streaming` | body、decompression、streaming 和 diagnostics | 改写请求侧 fingerprint |

## 改动归属决策

| 需求 | 首选位置 |
|---|---|
| 新增用户 builder/API | `lkrequest` 的 Client、Session 或 RequestBuilder |
| 新增跨协议 browser preset | `lkrequest/src/preset.rs`，引用各协议 profile |
| ClientHello 字段或顺序 | `lktls` 和对应 capture profile |
| H2 SETTINGS/HPACK/frame 行为 | `lkh2` |
| H3 SETTINGS/QPACK/header order | `lkh3` |
| QUIC socket/backend 生命周期 | `lkquic` |
| QUIC TLS secret/handshake bridge | `lktls-quic` |
| MASQUE 线上格式、capsule 分帧或隧道状态机 | `lkmasque` |
| MASQUE 的 socket/连接池/失败隔离 | `lkrequest`（`proxy::masque`、`session::masque`） |
| C ABI 暴露 | 先完成 Rust API，再在 `lkrequest-ffi` 映射 |
| 捕获解析或规范化 | `lkprofile` 或对应 tools crate |

不要在 FFI 复制业务实现，不要在 `lkrequest` 手工拼接协议 bytes，也不要为了绕过 profile 能力直接修改 patched submodule。

## 指纹不变量

协议合法不等于浏览器指纹正确。涉及 TLS record、HTTP frame、header order、GREASE、QUIC transport parameters 或发送时序的修改，需要同时验证：

- 目标浏览器的真实网络证据；
- 序列化字节或有序字段；
- 离线 golden/fixture 回归；
- feature 和协议 fallback 下的行为。

性能优化也必须明确其 wire-level 影响。无法证明边界保持不变的优化应保持可关闭，并且不得默认改变浏览器 preset。
