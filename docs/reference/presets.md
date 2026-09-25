# 指纹 preset 支持与验证矩阵

本页区分两件事：**API 可以构造某个完整 preset**，以及**该 preset 的每一协议层是否有直接外部证据**。数据源是 `docs/data/preset-evidence.toml`，审阅日期为 2026-09-25。

当前源码提供 17 个完整 preset，Rust 与 FFI 名称一致。Chrome 154 和 Firefox 156 是本次新增版本。

| 选择 | TLS / H2 | QUIC / H3 | 验证说明 |
|---|---|---|---|
| `chrome_154` | 支持 | 需要 `quic-h3` | TLS/H2、发出的 QUIC ClientHello 和传输参数已抓包；H3 SETTINGS 继承 Chrome 153 |
| `firefox_156` | 支持 | 未提供 | Firefox 156.0.1 的 TLS/H2 已抓包，库的完整 preset 已完成公网 H2 请求 |

支持范围按当前源码描述。使用发布包或固定 Git revision 时，应确认该版本包含所需 preset；FFI 可通过 `lk_preset_list_json` 查询实际可用名称。

## 状态定义

| 状态 | 含义 |
|---|---|
| verified | 有对应真实浏览器/客户端的直接抓包或回显证据 |
| inherited | 明确沿用另一个已验证版本的稳定字段 |
| partial | 只验证了部分字段、阶段或请求上下文 |
| fixture-only | 有离线 fixture/golden，可防止实现漂移，但没有足够外部证据 |
| unverified | 有实现，但现有资料明确不足 |
| — | 该完整 preset 不提供这一协议层 |

## 完整 preset

| Preset | 浏览器版本 | 平台 | Rust | FFI | H3 profile |
|---|---|---|---:|---:|---:|
| `chrome_131` | 131 | 未记录 | 是 | 是 | 是 |
| `chrome_144` | 144.0.0.0 | Windows 10 | 是 | 是 | 是 |
| `chrome_145` | 145 | 未记录 | 是 | 是 | 是 |
| `chrome_146` | 146 | Windows 11 | 是 | 是 | 是 |
| `chrome_147` | 147 | 未记录 | 是 | 是 | 是 |
| `chrome_148` | 148 | 未记录 | 是 | 是 | 是 |
| `chrome_149` | 149.0.7827.54 | 未记录 | 是 | 是 | 是 |
| `chrome_150` | 150.0.7871.47 | Windows | 是 | 是 | 是 |
| `chrome_151` | 151.0.7922.72 | Windows | 是 | 是 | 是 |
| `chrome_152` | 152.0.7977.65 | Windows | 是 | 是 | 是 |
| `chrome_153` | 153.0.8010.37 | Windows | 是 | 是 | 是 |
| `chrome_154` | 154.0.8037.58 | Windows | 是 | 是 | 是 |
| `firefox_133` | 133 | 未记录 | 是 | 是 | 否 |
| `firefox_147` | 147.0.3 | 未记录 | 是 | 是 | 否 |
| `firefox_156` | 156.0.1 | Windows | 是 | 是 | 否 |
| `safari_18` | 18 | 未记录 | 是 | 是 | 否 |
| `safari_26` | 26.2 | 未记录 | 是 | 是 | 否 |

`default` 是 FFI 对 `chrome_144` 的兼容 alias；`safari_26_2` 是 `safari_26` 的 FFI alias。Rust API 使用明确函数名。

H3 profile 的“是”要求构建时启用 `quic-h3`；“否”表示该 preset 本身没有 QUIC/H3 配置，即使启用 feature 也不会补齐。Firefox 和 Safari 可使用 H1/H2，但不能通过 `http3_only()` 获得对应浏览器的 H3 指纹。

## 协议层证据

| Preset | TCP TLS | H2 | QUIC TLS | QUIC transport | H3 SETTINGS |
|---|---|---|---|---|---|
| `chrome_131` | unverified | fixture-only | fixture-only | inherited | inherited |
| `chrome_144` | verified | fixture-only | fixture-only | inherited | inherited |
| `chrome_145` | partial | fixture-only | fixture-only | inherited | inherited |
| `chrome_146` | verified | verified | verified | verified | verified |
| `chrome_147` | verified | inherited | fixture-only | inherited | inherited |
| `chrome_148` | verified | inherited | fixture-only | inherited | inherited |
| `chrome_149` | verified | verified | fixture-only | inherited | inherited |
| `chrome_150` | verified | partial | partial | partial | partial |
| `chrome_151` | verified | verified | verified | inherited | inherited |
| `chrome_152` | verified | inherited | verified | partial | inherited |
| `chrome_153` | verified | verified | verified | verified | verified |
| `chrome_154` | verified | verified | verified | verified | inherited |
| `firefox_133` | unverified | fixture-only | — | — | — |
| `firefox_147` | verified | fixture-only | — | — | — |
| `firefox_156` | verified | verified | — | — | — |
| `safari_18` | unverified | fixture-only | — | — | — |
| `safari_26` | verified | fixture-only | — | — | — |

## 重要边界

- fixture 证明“当前实现没有相对仓库 golden 漂移”，不证明 golden 等于任意真实浏览器。
- Chrome 150 Outlook capture 显示 QUIC transport、PRIORITY_UPDATE、header order 和 packet layout 具有请求上下文差异，因此不能标为完整 wire parity。
- Chrome 152 直接验证了 TCP TLS 的 sigalgs GREASE slot、trust-anchor ID 集合，以及 QUIC ClientHello/部分 transport changes；完整 H3 SETTINGS 未被该次公共流量证明。
- Chrome 153 的公共抓包同时覆盖了 TCP TLS、H2、QUIC TLS、QUIC transport 与 H3：H3 导航返回 200，SETTINGS `1=65536`、`6=262144`、`7=100`、`51=1` 被直接观察到，因此这五层都标为 verified。profile 与回归 fixture 的路径记录在 `docs/data/preset-evidence.toml` 中。
- Chrome 154 的公共抓包验证了 TCP TLS、H2、QUIC TLS、QUIC transport 和 Initial packetization 与 Chrome 153 一致；当前路径没有收到 QUIC 回包，因此 H3 SETTINGS 明确继承 Chrome 153，不标为直接验证。
- Firefox 156 的公共抓包验证了 TLS 和 H2，也观察到 Firefox QUIC Initial；由于当前实现不能精确表达非对称 stream window、`max_ack_delay=20`、active CID limit 8 和 Firefox Initial 布局，因此公开 preset 不启用 QUIC/H3。QUIC 采集记录仅用于后续研究，不代表已有可用 profile，所以表中标为“—”。
- GREASE、extension order、CID、packet number、timing、ACK 和 retransmission 等随机/路径字段不能直接做整包 byte equality。Chrome 146 与 150–154 还额外包含逐连接生成的部分：保留 transport parameter 的 id 与 0–15 字节 payload、GREASE version 在可用版本列表中的位置、H3 保留 SETTINGS 的 id/value、control stream 上 0–3 字节的 GREASE 帧，以及 Initial 包内 CRYPTO 的拆分顺序与穿插的 PING/PADDING。这些字段只能按生成规则比对，不能按某一次抓包逐字节比对。
- preset 能完成请求不代表该协议层已验证。验证必须同时记录浏览器版本、平台、采集日期、目标和规范化规则。

选择和升级建议见[选择浏览器 preset](../guides/choosing-a-preset.md)。
