# 架构与 crate 边界

lkrequest 将高层会话状态、协议实现和线缆指纹控制分层隔离。修改应落在能够完整表达需求的最高层；只有确实需要改变序列化字节或传输行为时，才进入底层协议 crate。

本页面向贡献者，说明源码结构、设计不变量和修改归属。应用开发者应从[使用场景导航](../guides/)开始；只需要判断 Client 与 Session 生命周期时，阅读[用户对象模型](../guides/object-model.md)。

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
2. 解析 Client/Session/Request 的有效次数上限，建立请求执行生命周期与总 deadline；
3. middleware、retry 和 redirect 策略决定候选行为，恢复路径申请本次请求的授权；
4. transport 根据显式策略、Alt-Svc 与 QUIC 失败状态选择 H1/H2/H3，查询连接池或等待共享建链；
5. 必要时执行 DNS、TCP/UDP、代理、TLS 和协议握手，在实际启动后端连接时计数；
6. 在协议提交边界提交 HTTP permit，再由 response 层处理 body、解压和资源释放。

状态应由拥有其生命周期的层维护。例如 Cookie 与 HSTS 属于 Session，TLS 扩展顺序属于 `lktls` profile，H2 SETTINGS 属于 `lkh2` profile，QUIC transport parameters 属于 H3/QUIC profile。

### 执行授权与共享建链

`session::execution` 为每次公开操作保存 deadline、停止状态、HTTP 提交与建链计数。根执行 guard 结束后，派生引用不能继续授权提交；只读 observer 不拥有发送权限。普通响应完成时结束该操作，流式响应在 headers 发布时结束 HTTP 提交统计，后续 body 读取继续使用原 timeout。

`session::recovery` 检查具体的恢复条件、方法幂等性和 body 可重放性，再向当前执行申请授权。协议选择、应用 `RetryPolicy` 与 TLS/H2/H3 profile 仍由各自模块解释；执行层不把它们合并成一个全局策略调度器。

`session::acquisition` 按 Session 和连接键协调正在进行的建链。实际启动者使用自己的建链额度，等待者没有共享其 HTTP 权限或总 deadline。启动者退出后，等待者可以重新竞争启动资格；取消等待者不应取消启动者。已有物理连接的并发占用仍由 `connection_pool` 管理，与每次操作累计启动多少次连接是两项独立约束。

TCP/QUIC 竞速可产生多个连接尝试，但每个 HTTP attempt 只允许一次提交。复用已入池的 H2 连接与新建连接一样，必须在消费上传源和提交前检查竞速发送门控。连接计数、恢复获准数和 HTTP 提交数分开维护，不能互相推导。

## 高层模块职责

| 模块 | 职责 | 不应承担 |
|---|---|---|
| `client` / `preset` | 共享配置、跨协议 preset、默认策略 | 每个身份的 Cookie 或连接 |
| `session` | 请求 pipeline、身份状态和 protocol selection | TLS/H2/H3 字节序列化细节 |
| `attempts` / `attempt_observer` | 公开次数配置、有效值与只读摘要 | Session 物理连接占用 |
| `session::execution` | 单次操作的生命周期、deadline、授权与记账 | 浏览器 profile 或协议选择决策 |
| `session::recovery` | 恢复条件、重放安全与应用重试衔接 | 创建独立于当前请求的重发额度 |
| `session::acquisition` / `tcp_acquisition` | Session 内共享建链、启动者选举与就绪连接获取 | 跨请求共享 HTTP 提交权限 |
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
| 新增 HTTP 恢复路径 | 在 `session::recovery` 表达条件，复用 `session::execution` 的授权与提交计数 |
| 新增建链后端或候选连接 | 通过当前 `ConnectionExecution` 在实际启动边界申请额度，维持共享建链与物理 permit 语义 |
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
