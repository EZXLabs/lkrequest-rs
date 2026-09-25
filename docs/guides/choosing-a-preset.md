# 选择浏览器 preset

用户应通过 `lkrequest::preset` 中的完整 `ClientPreset` 选择浏览器，而不是分别拼接 TLS、H2 和 H3 profile。完整 preset 同时携带协议 profile、header order、协议选择策略和会话缓存分区策略；浏览器请求头的值由应用显式设置。

`Cookie` 头的顺序不来自 preset：内置 preset 的 `cookie_order` 都是 `None`，顺序由 Session 的 cookie jar 按 Chrome 规则决定（path 长的在前，长度相同则先创建的在前）。需要固定某几个 cookie 的位置时，用 `Client`、`Session` 或请求级的 `cookie_order()` 显式指定，未列出的 cookie 仍按上述规则排在其后。详见[请求配置](requests/README.md#cookie)。

## 当前公共 preset 名称

当前源码提供：

- Chrome：`chrome_131`、`chrome_144`–`chrome_154`；
- Firefox：`firefox_133`、`firefox_147`、`firefox_156`；
- Safari：`safari_18`、`safari_26`。

该列表表示 API 中可以构造完整 preset，不等同于每个平台、每一协议层都具有同等级的最新抓包证据。逐层证据见 [Preset 支持与验证矩阵](../reference/presets.md)。

| 需求 | 选择 | 协议范围 |
|---|---|---|
| Chrome 154 | `chrome_154` | TLS/H2；启用 `quic-h3` 后可用 QUIC/H3，H3 SETTINGS 继承 Chrome 153 |
| Firefox 156 | `firefox_156` | TLS/H2；不提供 QUIC/H3 profile |

Chrome 154.0.8037.58 与 Firefox 156.0.1 的采集平台均为 Windows。启用 `quic-h3` 不会为 Firefox 或 Safari preset 增加缺失的 QUIC/H3 配置。

## 显式固定版本

```rust,ignore
let client = Client::builder()
    .preset(lkrequest::preset::chrome_154())
    .build();
```

不要使用“最新 Chrome”作为不可审计的运行时概念。升级 preset 时应作为显式代码改动，并重新验证目标平台、TLS、H2，以及启用 H3 时的 QUIC/H3 层。

Firefox 156 示例：

```rust,ignore
use lkrequest::Client;

let client = Client::builder()
    .preset(lkrequest::preset::firefox_156())
    .default_header(
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0",
    )
    .build();
let session = client.session().http2_only().build();
```

这里显式要求 H2；不设置 `http2_only()` 时仍可按该 preset 的协议策略使用 H1/H2。

## FFI 名称

`lk_client_builder_set_preset(builder, "chrome_154")` 和
`lk_client_builder_set_preset(builder, "firefox_156")` 使用与 Rust 函数相同的规范名称。
`lk_preset_list_json` 列出加载的库实际提供的 preset；`lk_preset_get_detail_json` 返回指定规范名称的配置。
已发布的旧版本不一定包含本页的新 preset，绑定调用方应按实际库版本查询。

## User-Agent 与 preset

preset 不会自动填充 `User-Agent`、Client Hints 或 `Accept-Language`。通过 `default_header()` 或请求级 headers 设置这些值时，应与浏览器版本、平台和请求上下文保持一致。只设置 TLS profile 或 User-Agent 都不等于完整浏览器指纹。

如果目标要求自定义 User-Agent，应把它视为一个新的组合配置，并记录：

- 使用的 preset；
- 覆盖的 headers；
- header 发送顺序；
- 目标平台与浏览器版本；
- 实际抓包或回显验证结果。

## 真实 preset 与 randomization

- 不启用 randomization：保持 preset 定义的浏览器身份。
- extension-order jitter：仍基于真实 preset，但 JA3 等顺序敏感摘要可能变化。
- `synthetic-fp` 的 recombine/full：生成不对应任何真实浏览器的组合，仅适用于合成指纹研究。

合成模式不能用来宣称“模拟某个 Chrome 版本”，也不应对依赖 allowlist 的目标默认启用。

## 升级检查清单

1. 确认新 preset 在 `lkrequest::preset` 中存在。
2. 确认应用所需 feature，尤其是 `quic-h3`。
3. 对固定公开目标进行请求级验证。
4. 对 TLS/H2/H3 有序字段或 packet bytes 做离线比较。
5. 检查 headers 与协议选择是否同步变化；如果应用显式设置过 `cookie_order()`，确认它仍与目标站点的 cookie 名一致。
6. 保留旧版本回退路径，不要在同一部署中静默替换全部身份。
