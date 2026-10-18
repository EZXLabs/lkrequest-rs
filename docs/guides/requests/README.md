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
排序。按这个顺序写回一个新 Session，重建出的 jar 会发送完全相同的 `Cookie` 头。

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

严格 H3 请求继续使用 H3。其他请求只有在 `FallbackPolicy::AllowFallback` 且代理路由允许 TCP 时，才会在重试中暂时禁用该 hop 的 H3，并通过 TCP 协商 H1/H2。`NoFallback` 或仅允许网络错误回退的策略不会因此被放宽。重定向的新 hop 恢复原协议配置并获得独立预算，整条重定向链仍共用原总截止时间；外层 `RetryPolicy` 不会再次扩大已由此模式处理的重试链。该模式不改变 POST 的 0-RTT 发送资格，也不等同于 Chrome 的全部重试策略或完整连接选择行为。

请求体和响应读取分别见：[请求体](bodies.md)、[响应处理](responses.md)。
