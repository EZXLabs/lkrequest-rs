# 指纹随机化

lkrequest 的浏览器 preset 已经包含真实浏览器自身的连接级随机性：TLS 的 GREASE、key share 和部分顺序；Chrome 146 与 150–153 的 QUIC preset 还包含 H3/QUIC 层的逐连接随机，即保留 SETTINGS 与 GREASE 帧、保留 transport parameter 的 id/长度与 GREASE version 位置，以及 Initial 包内 CRYPTO 的拆分和穿插的 PING/PADDING。因此同一个 preset 的两次连接本来就不是逐字节相同的。`Randomize` 是额外策略，不是使用 preset 的必选项，也不能提升某个 preset 的真实浏览器一致性。

## 随机化层级

| 策略 | Cargo feature | 生命周期 | 结果 |
|---|---|---|---|
| `Randomize::off()` | 默认 | 使用 preset 原生行为 | 不添加额外随机化 |
| `Randomize::extension_order()` | 默认 | 每次新连接 | 对真实 TLS extensions 做浏览器形态的顺序置换 |
| `Randomize::recombine()` | `synthetic-fp` | 每个 Session | 从已知 preset 组件重组跨层 synthetic identity |
| `Randomize::full()` | `synthetic-fp` | 每个 Session | 在 H2/QUIC 可宣传数值上进一步生成 corpus 外取值 |

`recombine` 和 `full` 生成的不是任何真实浏览器版本。它们只适合有授权的负向模型、封禁规则和鲁棒性研究，不适合要求浏览器 allowlist 或真实 preset 一致性的目标。

## 默认与 extension order

```rust,ignore
use lkrequest::{preset, Client, Randomize};

let stable_client = Client::builder()
    .preset(preset::chrome_153())
    .randomize(Randomize::off())
    .build();

let shuffled_client = Client::builder()
    .preset(preset::chrome_153())
    .randomize(Randomize::extension_order())
    .build();
```

`extension_order()` 在每次新 TLS handshake 时置换 extension 顺序，同时保持 GREASE bookend 和 `pre_shared_key` 等位置约束。它可能让 JA3 随连接变化；JA4 会排序 extensions，因此通常不因这一策略变化。

连接池复用时不会为每个 HTTP request 重新握手。需要观察每连接随机化时，应明确控制 Session、连接池和目标 origin 的生命周期。

## 启用 synthetic fingerprint

```toml
[dependencies]
lkrequest = { git = "https://github.com/EZXLabs/lkrequest-rs", features = ["synthetic-fp"] }
```

```rust,ignore
use lkrequest::{preset, Client, Randomize};

let client = Client::builder()
    .preset(preset::chrome_153())
    .randomize(Randomize::recombine())
    .build();

let first_identity = client.session().build();
let second_identity = client.session().build();
```

同一个 Client 创建的不同 Session 会得到不同 synthetic identity；同一 Session 内保持身份一致，避免请求之间无意漂移。被选中的 TLS、H2 和 QUIC 层从同一个 seed 协调生成。每次连接仍会叠加上述连接级随机量（TLS 的 GREASE、key share，以及启用 H3 时的 QUIC/H3 生成部分）。

## 只随机化部分协议层

```rust,ignore
use lkrequest::{Layers, Randomize};

let tls_and_h2 = Randomize::recombine_layers(Layers::TLS | Layers::H2);
let quic_only = Randomize::full_layers(Layers::QUIC);
```

可选层为：

- `Layers::TLS`：TLS ClientHello，也驱动 QUIC-native TLS；
- `Layers::H2`：HTTP/2 SETTINGS、pseudo-header order 等；
- `Layers::QUIC`：QUIC transport parameters 与 HTTP/3 fingerprint，需要同时启用 `quic-h3`。

默认优先使用 `recombine()` 或 `full()` 的全层组合。只合成一层、其他层保持固定真实 preset，可能形成更容易识别的跨层异常；只有确认目标只观察特定层时才应使用 `*_layers(...)`。

## Negotiability floor

```rust,ignore
use lkrequest::{NegotiabilityFloor, Randomize};

let policy = Randomize::recombine()
    .negotiability(NegotiabilityFloor::PresetFamily);
```

negotiability floor 只作用于 `recombine` / `full`。默认值偏向广泛可协商；提高到 preset family 约束可以保留更多基础 preset 的协商特征，但仍不会把 synthetic identity 变成真实浏览器。

## 选择建议

1. 需要模拟已验证浏览器：使用完整 preset 和 `Randomize::off()`；
2. 只需连接级 TLS 顺序变化：使用 `extension_order()`；
3. 研究负向 fingerprint 模型：启用 `synthetic-fp`，优先全层 `recombine()`；
4. 需要 corpus 外 H2/QUIC 数值：再考虑 `full()`；
5. 每次变更后分别验证 TLS、H2、QUIC/H3 和 HTTP header 层，不能只比较 JA3。

随机化结果属于新的 wire identity，不继承基础 preset 的 verified 状态。真实浏览器 preset 的维护与证据流程见 [自定义指纹与验证](../../development/fingerprint-research.md) 和 [Preset 支持与验证矩阵](../../reference/presets.md)。

