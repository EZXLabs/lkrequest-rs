# Crate 功能与选型

lkrequest workspace 按使用层、协议层、传输层和绑定层拆分。**普通 Rust 应用只应直接依赖 `lkrequest`**；底层 crate 主要面向协议维护、指纹研究和自定义集成。

## 快速选型

| 你要做什么 | 直接依赖 |
|---|---|
| 发送同步或异步 HTTP 请求 | `lkrequest` |
| 使用 browser preset、代理、Cookie、retry、redirect、pool | `lkrequest` |
| C/C++ 或其他语言绑定 | `lkrequest-ffi` |
| 实现自定义 TCP TLS I/O adapter | `lktls` |
| 研究或嵌入 H2 codec/HPACK/frame engine | `lkh2` |
| 研究 H3/QPACK/QUIC profile | `lkh3` |
| 从另一个 QUIC 栈驱动 MASQUE CONNECT-UDP、实现 MASQUE 端点或调试其线上格式 | `lkmasque` |
| 替换或管理 QUIC backend/endpoint | `lkquic` |
| 维护 lktls 与 Quinn 的 TLS bridge | `lktls-quic` |
| 解析抓包并生成 fingerprint profile | `lkprofile` |

如果你的需求可以通过 `ClientBuilder`、`SessionBuilder`、preset 或 policy 表达，就不应该绕过 `lkrequest` 直接组装底层协议 crate。

## 依赖关系

```text
Application
   │
   ├──────────────► lkrequest-ffi ──► lkrequest
   │                                    │
   └────────────────────────────────────┤
                                        ├─► lktls
                                        ├─► lkh2
                                        ├─► [quic-h3]
                                        │     ├─► lkh3
                                        │     ├─► lkquic
                                        │     └─► lktls-quic
                                        │           └─► patched quinn / h3
                                        └─► [masque] ──► lkmasque

profile_collector / fpverify / pcap_diff ──► lkprofile and protocol crates
```

`quic-h3` 默认关闭，因此普通 H1/H2 使用不会编译 H3/QUIC 层。`masque` 也默认关闭并蕴含 `quic-h3`；它只额外引入 `lkmasque`，MASQUE 的 I/O 桥接本身在 `lkrequest` 内。

## `lkrequest`：高层客户端

面向最终应用的主要 crate，负责把协议能力组织成稳定的请求模型。

主要功能：

- `Client`、`Session`、blocking wrapper 和 request builder；
- browser `ClientPreset`，组合 TLS/H2/H3 profile 与 header order；
- Cookie、HSTS、Alt-Svc、QUIC failure cooldown 和 network partition；
- H1/H2/H3 protocol policy、connection pool 和 multiplexing；
- HTTP CONNECT、SOCKS5、SOCKS5 UDP、MASQUE CONNECT-UDP（`masque` feature）、proxy chain 和动态代理；
- retry、redirect、middleware、idempotency 和资源限制；
- streaming response、decompression、multipart 和 WebSocket；
- SessionPool、ProxyPool、preconnect、prefetch 和 diagnostics；
- 可选 DoH、telemetry、H3/QUIC 和 synthetic fingerprint research。

应用层行为、身份生命周期和协议选择应优先在这里实现。

## `lktls`：TLS wire fingerprint engine

Sans-I/O TLS 状态机，负责生成和处理 fingerprint-sensitive TLS 字节。

主要功能：

- TLS 1.2/1.3 handshake 与 record processing；
- ClientHello cipher、extension、GREASE、key share 和 signature algorithm 顺序；
- ECH、ALPS、certificate compression、session ticket 和 key export；
- JSON browser profiles 与 profile synthesis；
- 将网络 I/O 与 TLS 状态机分离，供 TCP 和 QUIC bridge 使用。

ClientHello 或 TLS record bytes 的变化属于该层。profile 必须来自真实 capture，不应手工修改 golden 迎合测试。

## `lkh2`：HTTP/2、HPACK 与 frame engine

原生 HTTP/2 连接实现；`lkrequest` 没有第二个 H2 backend。

主要功能：

- client preface、SETTINGS、WINDOW_UPDATE 和 connection lifecycle；
- HPACK encoder/decoder、动态表和 Huffman；
- pseudo-header/header order、重复 header 和 Chrome 风格 priority；
- HEADERS/DATA/PRIORITY/control frame emission；
- multiplexing、stream state、flow control 和响应事件；
- 可验证的 write batching 边界。

H2 SETTINGS、HPACK policy、frame bytes 或发送顺序变化属于该层。`h2-native` 只是将在 `0.3.0` 删除的兼容别名。

## `lkh3`：HTTP/3 与 QUIC profile

负责 HTTP/3/QPACK 行为和浏览器 QUIC profile 的上层表达。

主要功能：

- H3 control/request stream 与 SETTINGS；
- QPACK encoder/decoder 和 header order；
- QUIC transport parameter profile；
- request priority、Initial 包布局和浏览器 preset 数据；
- 按 Chromium 规则逐连接生成的随机部分：`H3Profile::chromium_grease`（保留 SETTINGS 的 id/value、control stream 上 0–3 字节的 GREASE 帧）、`QuicTransportParams::randomize_grease_shape`（保留 transport parameter 的 id 与 0–15 字节 payload、GREASE version 位置）、`QuicPacketizationProfile::initial_packet_chaos`（Initial 内 CRYPTO 的拆分与穿插的 PING/PADDING）；
- 与 patched `h3` session/stream API 的集成。

H3 SETTINGS、QPACK/header order 和 transport parameter 目标值属于该层。这些生成模式默认关闭，由 Chrome 146 与 150–153 的 QUIC preset 显式开启，自定义 profile 保持原有行为。

## `lkquic`：QUIC endpoint 与 backend

负责实际 UDP/QUIC endpoint、连接建立和 backend 生命周期，不定义高层 HTTP 请求语义。

主要功能：

- endpoint、socket、connection 和 connection statistics；
- Quinn backend 与 runtime 集成；
- direct UDP 与代理 UDP transport 接入；
- backend abstraction、连接关闭和资源管理。

自定义 QUIC backend 或 endpoint 生命周期属于该层；H3 header/SETTINGS 不属于该层。

## `lkmasque`：MASQUE CONNECT-UDP 线上格式与隧道状态机

Sans-I/O 的 MASQUE 客户端层：RFC 9298（Proxying UDP in HTTP）叠加在 RFC 9297（HTTP Datagram 与 Capsule Protocol）之上。由 `lkrequest` 的 `masque` feature 可选引入。

主要功能：

- QUIC 变长整数编解码（RFC 9000 §16）；
- 两层 HTTP Datagram 载荷 `[quarter stream ID][context ID][payload]`，含“无法识别的 Context ID 应丢弃而非报错”这条规则；
- `QuarterStreamId` newtype，使原始 stream ID 不会被误当作已除四的值；
- 最小 Capsule 分帧：读类型与长度、跳过未知类型、把截断视为格式错误；
- CONNECT-UDP URI Template 的展开与校验（含 IPv6 字面量冒号的百分号编码）；
- 载荷对两个独立尺寸上限的分类：65527 字节的协议上限（必须中止请求流）与隧道当前容量（普通丢弃）；
- 隧道状态机：构造 CONNECT-UDP 请求、按 RFC 9298 §3.5 校验响应（2xx，且满足它所引 RFC 9297 §3.2 的要求：非 204/205/206、不带 `content-length` / `content-type` / `transfer-encoding`；`capsule-protocol` 只做记录不做门禁，因为 §3.4 把它定为 SHOULD）、跨多次读取重组 capsule、内层 MTU 记账，以及按 Quarter Stream ID 解复用连接级 datagram 的 `TunnelTable`。

边界：

- **不做任何 I/O**，也不读时钟。每个函数只吃字节、标量或调用方提供的时间戳，返回字节、动作或错误。
- **只依赖 `thiserror`**，因此这一层的构建、测试和对照 RFC 审计都很便宜。
- **不涉及指纹**。到 MASQUE 代理的外层连接使用默认 TLS 配置；浏览器指纹属于内层连接，由 `lktls` / `lkh3` / `lkquic` 负责。

因为它对 TLS 指纹、Session 和 socket 都没有依赖，**可以独立使用**——从另一个 QUIC 栈驱动 CONNECT-UDP、实现 MASQUE 端点、写测试代理或调试线上分帧时直接依赖它即可。

**I/O 桥接不是独立 crate，而是放在 `lkrequest` 内**（`proxy::masque`）：它把隧道状态机驱动到本 workspace 打过补丁的 `h3` 与 `quinn` fork 上，并把每条隧道当作 `quinn::AsyncUdpSocket` 交给内层 QUIC 栈，只能针对这两个 fork 编译。把它留在外面，正是 `lkmasque` 能保持对任意 QUIC 栈可用的原因。

## `lktls-quic`：QUIC TLS bridge

将 `lktls` 的 TLS 1.3 handshake、secret export 和 browser profile 接入 Quinn crypto interface。

它处理 QUIC encryption level、handshake data 和 key transition，但不负责 HTTP/3 request，也不应复制 `lktls` 的 profile 逻辑。

## `lkprofile`：捕获数据解析

面向 profile collector 和验证工具的解析 crate。

主要功能：

- 解析 TLS ClientHello、extensions 和有序字段；
- 解析 H2 preface、SETTINGS、headers 与 frame sequence；
- 输出结构化 profile 候选和规范化数据；
- 为 fixture、差异报告和 capture-first 工作流提供基础。

它不是发送请求的客户端，也不代表解析出的 profile 已经获得真实浏览器验证。

## `lkrequest-ffi`：稳定 C ABI

将 `lkrequest` 对象模型映射成稳定的 C handles。

主要功能：

- Client、Session、Request、Response 和 StreamingResponse；
- ProxyPool、SessionPool、Multipart、DNS、logging 和 diagnostics；
- 同步调用与 opaque async operation handles；
- 错误对象、所有权、单次消费和线程边界；
- 可选 `quic-h3`、`doh`、`telemetry` 和 synthetic fingerprint surface。

`lkrequest.h` 由 cbindgen 在构建/发布流程生成，不在 Git 中跟踪。新增 Rust API 不自动代表 FFI 已经暴露。

## Workspace 工具

| 工具 | 功能 |
|---|---|
| `tools/profile_collector` | 捕获浏览器行为并生成 profile 候选 |
| `tools/fpverify` | 规范化随机字段并执行 fingerprint 回归 |
| `tools/pcap_diff` | 比较 ClientHello 或 packet bytes |
| `tools/http-client-bench` | 运行匹配 workload 的请求级 benchmark |
| `tools/cleaner` | 生成 public snapshot，排除 `design/` 和内部内容 |

## 各 crate 独立说明

- [`lkrequest`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkrequest/README.md)
- [`lktls`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lktls/README.md)
- [`lkh2`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkh2/README.md)
- [`lkh3`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkh3/README.md)
- [`lkquic`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkquic/README.md)
- [`lktls-quic`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lktls-quic/README.md)
- [`lkmasque`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkmasque/README.md)
- [`lkprofile`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkprofile/README.md)
- [`lkrequest-ffi`](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkrequest-ffi/README.md)

## API reference

初始化 submodule 后生成整个 workspace 的 rustdoc：

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

输出位于 `target/doc/`。高层使用从 `target/doc/lkrequest/index.html` 开始；只有维护对应协议时才进入底层 crate reference。

当前 crate 发布依赖图仍在整理中，metadata 中的 docs.rs 地址是预期入口，不代表每个底层 crate 已完成独立发布验证。
