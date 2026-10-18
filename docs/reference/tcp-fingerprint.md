# TCP 指纹的平台支持与限制

`TcpFingerprint` 通过操作系统的 socket API 调整新建 TCP 连接。TCP SYN、options 排列和窗口协商仍由实际运行的内核生成，因此它提供的是受平台限制的参数调整，**不保证完整 JA4T 匹配，也不能把一个平台的 TCP 栈变成另一个平台的 TCP 栈**。

本页描述当前实现的应用路径，不代表已在所有 Windows、Linux、macOS 版本上完成抓包验证。TLS、H2、QUIC/H3 的 preset 验证结论也不能作为 TCP SYN 已匹配的证据。

## 各平台哪些设置会应用

表中的“应用”指建连前调用对应的系统 API；内核接受、修正或拒绝参数，以及最终线缆输出，仍需在运行环境中确认。

| 配置 | Windows | Linux | macOS | 生效范围与限制 |
|---|---|---|---|---|
| `ttl` | 应用 | 应用 | 应用 | IPv4 设置 `IP_TTL`，IPv6 设置 `IPV6_UNICAST_HOPS`。这是本机发出的初始值，目标收到的值还受路由跳数影响；不属于 JA4T 四字段。 |
| `tcp_nodelay` | 应用 | 应用 | 应用 | 设置 `TCP_NODELAY`，影响 Nagle 和小包发送行为，不改写 SYN options。未配置指纹时库也默认启用；显式 `false` 可覆盖。 |
| `recv_buf_size` | 应用 | 应用 | 应用 | 设置 `SO_RCVBUF`，优先于窗口字段的推导值。设置缓冲区不等于直接设置 SYN window 或 Window Scale。 |
| `send_buf_size` | 应用 | 应用 | 应用 | 设置 `SO_SNDBUF`，受系统缓冲区限制；不直接控制对外通告的接收窗口。 |
| `window_size` + `window_scale` | 间接影响 | 间接影响 | 间接影响 | 两者同时存在才推导 `SO_RCVBUF`；只设置其中一个不会据此修改 socket。最终窗口和 scale 由内核选择，不能保证等于配置值。 |
| `mss` | 仅保存 | 应用 | 仅保存 | 当前只有 Linux 调用 `TCP_MAXSEG`。Windows/macOS 上不应用此字段，仍可用于 JA4T 字符串输出。 |
| `tcp_options` | 仅保存 | 仅保存 | 仅保存 | 不添加、删除或重排真实 SYN options；列表中的 SACK、Timestamps、NOP、Window Scale 等只描述目标。 |
| `keepalive.enabled = true` | 应用 | 应用 | 应用 | 通过 `socket2` 启用 TCP keepalive，并传递已指定的 `idle` / `interval`；时间精度和合法范围由平台决定。影响建连后的探测，不属于 JA4T。 |
| `keepalive.enabled = false` | 跳过 | 跳过 | 跳过 | 当前实现不执行 keepalive 配置，也不调用显式关闭 API；`idle` / `interval` 此时不应用。 |

“仅保存”通常不会导致连接失败。真正执行的 socket 设置若被系统拒绝，则当前地址的连接尝试返回错误；多地址拨号可能继续尝试其他地址，若所有尝试均失败或达到连接超时，请求返回错误。缓冲区被内核截断或调整也可能不报错，所以连接成功不等于指纹匹配。

## 窗口大小与缩放因子

当前接收缓冲区的选择顺序是：

1. 设置了 `recv_buf_size`：直接将其作为 `SO_RCVBUF` 的请求值。
2. 否则，同时设置了 `window_size` 与 `window_scale`：以 `window_size * 2^window_scale` 推导缓冲区；Linux 再除以 2，以对应内核的缓冲区计账方式。
3. 否则，不调整接收缓冲区。

这只是缓冲区推导规则，不是 SYN window 与 scale 的精确反算公式。SYN 中的 window 字段本身不按 scale 放大；缩放适用于协商后的窗口，见 [RFC 7323 §2.2](https://datatracker.ietf.org/doc/html/rfc7323#section-2.2)。不要把 `SO_RCVBUF`、SYN window 和后续连接的有效接收窗口视为同一个数值。

### Linux

- `SO_RCVBUF` / `SO_SNDBUF` 受 `net.core.rmem_max` / `net.core.wmem_max` 等限制；Linux 对这些缓冲区采用内部加倍计账，因此查询到的值也可能不同于传入值。库不使用 `SO_RCVBUFFORCE` 或 `SO_SNDBUFFORCE` 绕过限制。见 [Linux socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html)。
- 显式设置 `SO_RCVBUF` 会关闭该 socket 的接收缓冲区自动调优；此时 `tcp_rmem` 的自动调优上限不能替代 `rmem_max`。`tcp_window_scaling`、`tcp_timestamps`、`tcp_sack` 等系统配置仍会影响行为，库不会修改这些配置。见 [Linux IP sysctl 文档](https://docs.kernel.org/networking/ip-sysctl.html)。
- `mss` 在 `connect()` 前通过 `TCP_MAXSEG` 应用，可影响 SYN 中的 MSS；合法范围、接口 MTU 等仍有限制，不能任意强制一个线上值。见 [Linux tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html)。

### Windows

- 库会请求 TTL/Hop Limit、收发缓冲区、Nagle 和 keepalive 设置；接收窗口及缩放仍取决于 Windows TCP 栈和系统策略，不采用 Linux 的缓冲区除以 2 规则。
- `mss` 在当前 Windows 实现中跳过；修改它只会改变配置和 `to_ja4t()` 输出，不会调用 MSS 设置 API。
- `tcp_options` 不会切换 Windows 的 Timestamps、SACK 或 options 顺序。操作系统存在某个 socket 选项，不意味着 `TcpFingerprint` 已接入它，例如 Winsock 的 `TCP_TIMESTAMPS`。见 [Microsoft TCP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options)。

### macOS

- 库会请求 TTL/Hop Limit、收发缓冲区、Nagle 和 keepalive 设置；窗口及 scale 由 Darwin TCP 栈决定，同样不采用 Linux 的缓冲区除以 2 规则。
- `mss` 在当前 macOS 实现中跳过。这是本库的实现边界，不能解释为“macOS 完全没有 MSS 配置能力”；例如 Apple 的 Network framework 提供 [`maximumSegmentSize`](https://developer.apple.com/documentation/network/nwprotocoltcp/options/maximumsegmentsize)，本库没有使用该接口。
- `tcp_options` 仅保存目标列表，不改写 Darwin 生成的 SYN options。

## Preset 与 JA4T 字符串的含义

`Client::builder().preset(...)` 不会自动设置 `TcpFingerprint`。TCP 配置需要单独通过 `.tcp_fingerprint(...)` 传入；不传入时仍保留库默认的 `TCP_NODELAY=true`。

`TcpFingerprint::chrome()` / `firefox()` 按**编译目标 OS**选择 TCP 模板。`chrome_win()`、`chrome_linux()`、`chrome_macos()` 等显式模板只是目标参数集合，不会切换内核，也不证明适用于该系统的每个版本、网卡或网络路径。

例如，在 Linux 上使用 `chrome_win()`，TTL、缓冲区、MSS、Nagle 会按 Linux 路径尝试应用，但实际 SYN options 仍由 Linux 生成；在 Windows 上使用 `chrome_linux()`，其 MSS 与 options 列表也不会被应用。

`from_ja4t()` 解析目标字段，`to_ja4t()` 序列化配置字段；两者都不读取 socket 的实际值、不采集 SYN，也不验证平台是否能生成目标指纹。C ABI 的 `lk_client_builder_set_tcp_fingerprint_ja4t` 使用同一解析和应用路径，具有相同限制；JA4T 字符串不包含 TTL、Nagle 或 keepalive 设置。

## 直连、代理与 HTTP/3

| 连接路径 | 本配置作用的位置 | 目标服务器看到的 TCP 指纹 |
|---|---|---|
| 直连 TCP，包括 H1/H2 | 客户端到目标的新建 TCP socket，在 `connect()` 前应用 | 由客户端实际 TCP 栈生成，并可能受中间网络设备影响 |
| HTTP CONNECT / SOCKS5 / 多跳 TCP 代理链 | 客户端到第一跳代理的 TCP socket | 由最后一跳代理面向目标建立连接时的 TCP 栈生成；客户端配置不会传递过去 |
| HTTP/3 / QUIC | 不应用于承载 QUIC 的 UDP 数据报 | 没有对应的 TCP SYN / JA4T；SOCKS5 UDP relay 的 TCP 控制连接是另一条连接 |

连接池复用已有 TCP 连接时不会重新发送 SYN，也不会重新应用配置。验证修改后行为需要创建新连接，例如使用新的 Session。WSL、容器或虚拟机中的 TCP 行为取决于实际建立连接的网络栈；仅修改浏览器 preset 或 User-Agent 不会改变它。

### 代理能否覆盖本机限制

**普通 HTTP CONNECT / SOCKS5 代理可以让目标看到代理出口的 TCP 指纹，从而绕开本机平台的部分限制，但不能保证任意指定或完整匹配 JA4T。** 这类代理会建立两段独立的 TCP 连接：

```text
lkrequest -- TCP 连接 A --> 代理 -- TCP 连接 B --> 目标网站
```

目标网站观察的是连接 B，由代理出口实际使用的网络栈生成；第一跳代理仍能观察连接 A 的客户端 TCP 指纹。多跳代理链同理，以最后一跳面向目标建立的连接为准。

| 需求或限制 | 通过普通 TCP 代理后的结果 |
|---|---|
| 不让目标看到本机 Windows/Linux/macOS 的 TCP SYN 指纹 | 可以，目标看到代理出口生成的 SYN。 |
| 本机无法设置 MSS、窗口或 options 顺序 | 可以换成代理出口生成的值；出口自身仍受内核、MTU、系统配置等限制。 |
| 完整匹配某个平台浏览器的 JA4T | 不保证；需要选择或控制合适的出口网络栈，并验证实际 SYN。 |
| 用本地 `.tcp_fingerprint(...)` 控制代理到目标的连接 | 不可以；配置只应用于连接 A，不会通过 CONNECT / SOCKS5 传递给连接 B。 |
| 统一 Nagle、缓冲区、keepalive 等连接行为 | 两段连接分别控制；本地设置仍可能影响客户端到代理的延迟、吞吐和保活行为。 |

例如，Windows 上运行 lkrequest，经使用 Linux 内核 TCP 栈的代理出口访问目标，目标通常看到 Linux 风格的 TCP 指纹。选择 Windows 浏览器的 TLS preset 不会把这一段 TCP 变成 Windows 风格；TLS 配置与出口 TCP 栈需要分别验证。代理服务标注的国家、城市或住宅 IP 类型，也不构成 TCP 指纹匹配的证据。

上述结论适用于**接收客户端 TCP 连接并另建出口 TCP 连接**的代理。纯转发 IP 数据包的 VPN/三层隧道不一定替换内层 TCP 指纹，不能仅凭使用了 VPN 或 TUN 就认定限制已被覆盖；应确认实际转发方式。HTTP/3 使用 UDP，不存在对应的 TCP SYN / JA4T，也不适用这套 TCP 覆盖判断。

## 如何确认实际生效

1. 固定运行 OS/内核版本、IPv4/IPv6、接口 MTU、代理/VPN 路径与配置，在同一环境比较真实浏览器和 lkrequest。
2. 让双方各自建立新 TCP 连接，抓取最初的客户端 SYN，逐项比较原始 window、MSS、Window Scale、options 的种类和顺序，以及 TTL/Hop Limit。
3. 同时检查 socket 设置错误和实际缓冲区值；这些只能证明系统调用结果，最终仍以抓包为准。`tcp_fingerprint: applied to socket` 日志中的 JA4T 来自配置，不是测量结果。
4. 通过代理时分别检查客户端到代理、代理到目标两段。若关注服务器检测结果，应以目标侧观察为准，不能用第一段的 SYN 代替。

Nagle、keepalive、分段和发送时序需要观察建连后的流量。`TCP_NODELAY=true` 不保证一次 write 对应一个 TCP 包；相关边界见 [HTTP/2 Write Batching 与指纹边界](../development/h2-write-batching.md)。

实现依据：[`TcpFingerprint` 与建连前应用逻辑](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkrequest/src/tcp_fingerprint.rs)、[代理连接](https://github.com/EZXLabs/lkrequest-rs/blob/main/lkrequest/src/proxy/connect.rs)。完整指纹验证流程见 [自定义指纹与验证](../development/fingerprint-research.md)。
