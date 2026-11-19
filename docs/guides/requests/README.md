# 请求配置

请求从 `Session` 创建。`Client` 上的 `get`、`post` 等便捷方法会创建临时 Session，不适合需要 Cookie、连接复用或协议发现状态的连续请求。

## Method 与 URL

常用 method 有直接入口，也可以使用任意 `http::Method`：

```rust,ignore
use http::Method;

let get = session.get("https://example.com/items");
let custom = session.request(Method::OPTIONS, "https://example.com/items");
```

URL 必须包含 scheme。解析错误会在 `send()` 时以 `Error::UrlParse` 返回。

## Query 参数

`query()` 保留 URL 中已有参数，并按调用顺序追加新参数：

```rust,ignore
let response = session
    .get("https://example.com/search?lang=zh")
    .query(&[("q", "rust"), ("page", "1")])
    .send()
    .await?;
```

## Headers 与顺序

Client 默认 header 会应用到它创建的 Session。单次请求的同名 header 覆盖默认值：

```rust,ignore
let client = Client::builder()
    .preset(preset::chrome_153())
    .default_header("accept-language", "zh-CN,zh;q=0.9")
    .build();

let response = client
    .session()
    .build()
    .get("https://example.com")
    .header("accept", "application/json")
    .send()
    .await?;
```

指纹敏感场景优先使用 preset 自带顺序。`headers_ordered()`、`header_order()` 和 `h3_header_order()` 会改变序列化顺序，不应仅为了代码整洁随意重排。

字符串形式的 `header()` 在名称或值无效时会跳过该 header。需要显式处理解析错误时，先构造 `HeaderName`/`HeaderValue`，再使用 `header_typed()`。

### HTTP/1.1 Header 大小写

HTTP/1.1 默认将字段名写成 Title-Case，例如 `Content-Type`。需要保留 `Host`、将其他字段名写成小写时，在创建 Client 时关闭转换：

```rust
let client = lkrequest::Client::builder()
    .http1_title_case_headers(false)
    .build();
```

此设置适用于普通请求、流式请求、预连接和 WebSocket 握手，包括自动生成的字段名：`Host` 保持首字母大写，`content-length` 等其他字段为小写；字段值和顺序不受影响。HTTP/2 与 HTTP/3 的字段名始终为小写。该选项不保留调用 `header()` 时传入的原始大小写。

C ABI 使用 `lk_client_builder_set_http1_title_case_headers(builder, false)`，同样保留 `Host` 的首字母大写。现有客户端与浏览器 preset 的默认行为保持 Title-Case；此模式本身不代表与某个浏览器的原始 HTTP/1.1 请求完全一致。

## Cookie

Session 自动保存响应中的 Cookie，并在后续匹配请求中发送：

```rust,ignore
session.set_cookie("https://example.com", "locale", "zh-CN");

let response = session
    .get("https://example.com/account")
    .cookie_override("token", "request-specific-token")
    .send()
    .await?;
```

- `cookie()` 追加请求级 Cookie；同名、不同 path 的 jar Cookie 仍可能一起发送。
- `cookie_override()` 替换该请求中所有同名 jar Cookie。
- 不同 Session 的 Cookie jar 相互隔离。

### 读取 jar 中的 Cookie

| 方法 | 返回 | 用途 |
|---|---|---|
| `get_cookies(url)` | `Vec<(String, String)>` | 会发往该 URL 的名值对 |
| `get_cookie(url, name)` | `Option<String>` | 同名时返回 path 最长的那个 |
| `get_cookie_values(url, name)` | `Vec<String>` | 同名的全部值，path 长的在前 |
| `get_cookies_with_attrs(url)` | `Vec<CookieInfo>` | 同 `get_cookies`，但保留完整属性 |
| `get_all_cookies()` | `Vec<CookieInfo>` | 跨所有域名的未过期 Cookie，按创建时间从早到晚 |
| `cookie_header(url)` | `Option<String>` | 该 URL 将要发送的完整 `Cookie` 头 |

`CookieInfo` 带有 `name`、`value`、`domain`、`host_only`、`path`、`secure`、
`http_only`、`same_site` 和 `expires_unix`，以及 `is_persistent()`。名值对无法区分
同名不同 path 的两个 Cookie，也无法回答“jar 里有这个 Cookie，为什么没带上”——答案
总是在属性里。blocking `Session` 上有同名方法。

```rust,ignore
for cookie in session.get_cookies_with_attrs("https://example.com/api/users") {
    println!("{}={} path={} secure={}", cookie.name, cookie.value, cookie.path, cookie.secure);
}
```

持久化登录态时用 `get_all_cookies()`：它跨域名返回，跳过已过期的条目，并按创建时间
排序。恢复时需保留 domain/host-only、path、安全属性与有效期，并按此顺序写回；仅恢复
name/value 不能保留原 Cookie 的作用域。Cookie 在恢复前过期时应丢弃。

### 写入、恢复与删除

```rust
let session = lkrequest::Client::builder().build().session().build();
session.set_cookie_with_attrs(
    "https://example.com/api", "token", "value",
    Some("/api"), None, true, true,
);
session.set_cookie_raw(
    "https://example.com", "locale=zh-CN; Path=/; Secure; SameSite=Lax",
);
assert_eq!(session.get_cookie("https://example.com", "locale").as_deref(), Some("zh-CN"));
session.remove_cookie("https://example.com", "locale");
session.clear_cookies();
```

`set_cookie_with_attrs()` 可设置 path/domain/Secure/HttpOnly，但不接收 SameSite 或 expiry；
需要这些属性时使用合法的 `Set-Cookie` 字符串和 `set_cookie_raw()`。host-only Cookie
应省略 Domain，恢复持久 Cookie 时保留绝对 Expires，不能重新赋予原 Max-Age 时长。
raw 入口与服务端 `Set-Cookie` 一样校验 Secure 和 `__Host-` / `__Secure-` 前缀规则；
typed setter 用于调用方显式导入，不执行同样的前缀检查。这些 setter 不返回 Result，
需要确认写入结果时读取 jar。

`remove_cookie(url, name)` 删除该主机的 `/` 路径条目，不是按名称删除全部 domain/path
变体。删除特定变体可用带相同 Domain/Path 且 `Max-Age=0` 的 raw Set-Cookie；清空整个
Session 用 `clear_cookies()`。C ABI 有属性写入、读取与清理入口，但没有 raw Set-Cookie
写入接口，不能据此宣称可以无损导入所有 Cookie 属性。

### 发送顺序

`Cookie` 头按 Chrome 的规则排列：**path 长的在前，path 长度相同则先创建的在前**
（Chromium `CookieMonster::CookieSorter`）。用相同的值重新设置一个 Cookie 会保留它
原来的创建时间；换成新值则视为新 Cookie，排到最后。

顺序属于指纹的一部分，因此它由 Session 的 cookie jar 决定，而不是由浏览器 preset
携带——内置 preset 的 `cookie_order` 都是 `None`。需要把某几个 Cookie 固定在前面
时，用 `Client`、`Session` 或请求级的 `cookie_order()` 指定名称列表；未列出的
Cookie 仍按上述规则排在它们之后。

## Timeout、重定向与重试

- Client timeout 是共享默认值；请求级 `timeout()` 覆盖单次请求总时间。
- Session 默认跟随最多 10 次 redirect；使用 `RedirectPolicy::None` 可返回原始 3xx。
- retry policy 属于 Session。非幂等请求不会仅因普通 timeout/reset 被盲目重放。
- 对带幂等键的 POST，可使用 `idempotency(Idempotency::Idempotent)` 明确声明可重放；声明错误可能造成重复写入。
- `send_streaming()` 不执行普通 `send()` 的自动 redirect 和 Session retry 流程。

## 请求优先级

```rust,no_run
use lkrequest::{Client, lkh2::RequestPriority};

# async fn example() -> Result<(), lkrequest::error::Error> {
let session = Client::builder().build().session().build();
let response = session.get("https://example.com/image.png")
    .priority(RequestPriority::image())
    .send().await?;
# Ok(())
# }
```

`priority()` 设置 HTTP priority 及 profile 定义的 urgency-to-weight 映射；启用对应行为的
H3 profile 也用它生成请求流 PRIORITY_UPDATE。默认由 profile 决定，设置它不是本地任务
调度优先级。`h2_priority_weight(0..=255)` 独立覆盖 H2 HEADERS 中的原始 weight，不改
HTTP priority、dependency 或 exclusive；没有 legacy priority 的 profile 不会因此添加它，
H1/H3 不受影响。C ABI 提供 `lk_request_set_h2_priority_weight`，没有等价的
`RequestPriority` setter；单独写 `Priority` header 不等于控制这些帧级行为。

### 显式 HTTP/3 兼容重试

启用 `quic-h3` 后，可以为 Session 选择 `H3RetryMode::Chrome155ProtocolErrors`：

```rust,ignore
use lkrequest::retry::H3RetryMode;

let session = client.session()
    .http3_only()
    .h3_retry_mode(H3RetryMode::Chrome155ProtocolErrors)
    .build();
```

此模式在 H3 sender 尚未返回响应头时，对选定的协议错误最多额外重试两次。它适用于无请求体或已缓冲的请求体，包括可能已被服务端处理的 POST，因此可能重复产生服务端副作用。默认 `Safe` 和所有 preset 均不会自动启用它；单次请求的 `Idempotency::NotIdempotent` 可禁止这些额外重试。

内部已经解码但尚未交给请求事务的早期响应头，不等于事务已经收到响应。响应正文或 trailer 阶段的协议错误不会触发此模式，一次性 streaming upload 也不会重放。`send()` 和 `send_streaming()` 都支持上述响应头之前的兼容重试；后者仍不执行普通 redirect 或状态码重试。

严格 H3 请求继续使用 H3。其他请求只有在 `FallbackPolicy::AllowFallback` 且代理路由允许 TCP 时，才会在重试中暂时禁用该 hop 的 H3，并通过 TCP 协商 H1/H2。`NoFallback` 或仅允许网络错误回退的策略不会因此被放宽。重定向的新 hop 恢复原协议配置和该模式的局部重试额度，但整条重定向链仍共用请求级 `AttemptLimits` 与原总截止时间；外层 `RetryPolicy` 不会再次扩大已由此模式处理的重试链。该模式不改变 POST 的 0-RTT 发送资格，也不等同于 Chrome 的全部重试策略或完整连接选择行为。

请求体和响应读取分别见：[请求体](bodies.md)、[响应处理](responses.md)。
