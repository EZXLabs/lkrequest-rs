# 自定义指纹与验证

完整 browser preset 是经过跨层组合的基线。自定义一个 TLS profile、header 顺序或 H2/H3 参数后，结果应视为新的 wire identity，不能继续继承原 preset 的完整验证结论。

如果目标不是维护真实浏览器 preset，而是需要连接级 extension shuffle 或跨层 synthetic identity，请先阅读 [指纹随机化](../guides/advanced/randomization.md)。随机化与浏览器版本复刻是两种不同目标。

## 先确定修改属于哪一层

| 需要改变的内容 | 所属层 |
|---|---|
| ClientHello extension、cipher、GREASE、key share、ALPS | `lktls` TLS profile |
| H2 SETTINGS、pseudo-header、HPACK、priority、frame 顺序 | `lkh2` H2 profile |
| QUIC transport parameters、H3 SETTINGS、QPACK/header order | `lkh3` QuicProfile |
| H3/QUIC 的 GREASE 生成规则与 Initial 包内帧布局 | `lkh3` 的 `H3Profile::chromium_grease`、`QuicTransportParams::randomize_grease_shape`、`QuicPacketizationProfile::initial_packet_chaos` |
| UDP endpoint、socket 和 QUIC backend 生命周期 | `lkquic` |
| 默认 HTTP headers、header order 和协议组合 | `lkrequest::ClientPreset` |
| `Cookie` 头顺序 | Session 的 cookie jar（Chrome `CookieSorter` 规则）；`cookie_order()` 可覆盖 |
| TCP 缓冲区、MSS、TTL；目标 window/scale 与 options 描述 | `TcpFingerprint`，受[平台限制](../reference/tcp-fingerprint.md)，不保证改写完整 SYN |

修改应放在能够完整表达行为的最高层。不要通过 patch 底层序列化结果绕过 profile 模型。

## 推荐验证流程

1. 固定浏览器完整版本、平台、实验配置、目标和采集时间；
2. 保存真实浏览器 capture，并区分稳定字段与随机/路径字段；
3. 从最接近的完整 preset 开始，每次只修改一个协议层；
4. 使用 profile collector 或解析工具生成结构化字段；
5. 对 GREASE、CID、packet number 等**取值**随机的字段做位置保持的规范化；对**形状**随机的部分（GREASE payload 长度、保留 SETTINGS 的取值、Initial 内 CRYPTO 的拆分与 PING/PADDING 排布）则比对生成规则与取值范围，而不是某一次抓包的具体布局；
6. 使用 fixture/golden 阻止实现漂移；
7. 再通过真实公共目标或受控服务确认实际线缆输出；
8. 在支持矩阵中标记 verified、inherited、partial、fixture-only 或 unverified。

fixture 只能证明当前实现与仓库 golden 一致，不能单独证明 golden 等于真实浏览器。请求成功、JA3 相同或聚合 hash 相同也不能覆盖 extension order、H2 frame、QUIC transport 和发送时序差异。

## 工具职责

| 工具 | 用途 |
|---|---|
| `tools/profile_collector` | 从浏览器/抓包提取 profile 候选数据 |
| `tools/pcap_diff` | 比较 ClientHello 或 packet bytes |
| `tools/fpverify` | 对随机字段规范化并执行离线 fingerprint gate |
| `lkprofile` | 解析 TLS ClientHello 和 H2 frame 为结构化 profile |

原始抓包、TLS key log、内部目标和未经脱敏的请求不能放入 `docs/`。公开文档只保留可复现的方法、经过审阅的矩阵和不包含敏感内容的结论。

当前 preset 的逐层证据见 [Preset 支持与验证矩阵](../reference/presets.md)。
