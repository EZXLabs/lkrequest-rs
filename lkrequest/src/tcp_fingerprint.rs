//! TCP fingerprint configuration for JA4T anti-detection.
//!
//! Modern WAFs (e.g. Cloudflare, Akamai) inspect TCP-level parameters from the
//! SYN packet to fingerprint the client OS and detect non-browser traffic.
//! This module requests socket settings that can influence some of these
//! parameters. The host kernel still generates TCP packets; a configured JA4T
//! string is a target description, not a guarantee of the observed fingerprint.
//!
//! # JA4T Format
//!
//! JA4T is a TCP fingerprinting method that captures four fields from the SYN:
//!
//! ```text
//! {window_size}_{tcp_options}_{mss}_{window_scale}
//!
//! Example: 64240_2-4-8-1-3_1460_8
//! ```
//!
//! | Part | Description | Example |
//! |------|-------------|---------|
//! | A    | TCP Window Size | `64240` |
//! | B    | TCP Options (kind numbers, dash-separated, SYN order) | `2-4-8-1-3` |
//! | C    | Maximum Segment Size (MSS) | `1460` |
//! | D    | Window Scale factor | `8` |
//!
//! # Platform notes
//!
//! The following describes this library's implementation, not every capability
//! offered by each OS or a packet-capture verification of every OS version.
//!
//! | Setting | Windows | Linux | macOS |
//! |---------|---------|-------|-------|
//! | IPv4 TTL / IPv6 unicast Hop Limit | Applied | Applied | Applied |
//! | `TCP_NODELAY`, receive/send buffers | Applied | Applied | Applied |
//! | Window size + scale | Indirect via receive buffer | Indirect via receive buffer | Indirect via receive buffer |
//! | MSS (`TCP_MAXSEG`) | Stored only | Applied before connect | Stored only |
//! | TCP options presence/order | Stored only | Stored only | Stored only |
//! | Keepalive when enabled, with optional idle/interval | Applied | Applied | Applied |
//!
//! Applied settings remain subject to OS limits and errors. Window size and
//! scale must both be present to derive `SO_RCVBUF`; an explicit receive buffer
//! overrides that calculation. Neither the SYN window nor its scale is directly
//! controlled. On Linux, buffer limits and explicit-buffer autotuning changes
//! also matter. TCP options remain kernel-generated on all three platforms.
//!
//! Settings apply to new TCP sockets, including the client-to-first-proxy hop.
//! The target sees the final proxy's TCP stack when a proxy originates that
//! connection. Reused connections have no new SYN; QUIC data uses UDP and is
//! unaffected. [`TcpFingerprint::to_ja4t`] serializes configuration, not traffic.

use std::fmt;
use std::time::Duration;

use crate::error::{connect_execution_io, take_connect_execution_io, Error};
use crate::session::execution::ConnectionExecution;

// ---------------------------------------------------------------------------
// TcpOption — TCP option kinds for JA4T
// ---------------------------------------------------------------------------

/// TCP option kind values as used in JA4T fingerprinting.
///
/// These represent the option types present in the TCP SYN packet.
/// The order of options is determined by the OS kernel and cannot be
/// changed via socket options.
///
/// # Common option orders by OS
///
/// | OS | Options | JA4T Part B |
/// |----|---------|-------------|
/// | Linux | MSS, SACK, TS, NOP, WS | `2-4-8-1-3` |
/// | Windows 10+ | MSS, NOP, WS, NOP, NOP, SACK | `2-1-3-1-1-4` |
/// | macOS/iOS | MSS, NOP, WS, NOP, NOP, TS, SACK, EOL | `2-1-3-1-1-8-4-0` |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[repr(u8)]
pub enum TcpOption {
    /// End of Option List (kind 0).
    EOL = 0,
    /// No-Operation / Padding (kind 1).
    NOP = 1,
    /// Maximum Segment Size (kind 2).
    MSS = 2,
    /// Window Scale (kind 3).
    WindowScale = 3,
    /// SACK Permitted (kind 4).
    SACKPermitted = 4,
    /// Timestamps (kind 8).
    Timestamps = 8,
}

impl TcpOption {
    /// Create from raw kind number.
    pub fn from_kind(kind: u8) -> Option<Self> {
        match kind {
            0 => Some(Self::EOL),
            1 => Some(Self::NOP),
            2 => Some(Self::MSS),
            3 => Some(Self::WindowScale),
            4 => Some(Self::SACKPermitted),
            8 => Some(Self::Timestamps),
            _ => None,
        }
    }

    /// Return the raw kind number.
    pub fn kind(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for TcpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind())
    }
}

// ---------------------------------------------------------------------------
// TcpKeepalive
// ---------------------------------------------------------------------------

/// TCP keep-alive parameters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TcpKeepalive {
    /// Enable keep-alive.
    pub enabled: bool,
    /// Idle time before the first keep-alive probe.
    pub idle: Option<Duration>,
    /// Interval between keep-alive probes.
    pub interval: Option<Duration>,
}

// ---------------------------------------------------------------------------
// TcpFingerprint
// ---------------------------------------------------------------------------

/// TCP fingerprint configuration targeting JA4T anti-detection.
///
/// Requests TCP socket settings for a target fingerprint, subject to the
/// [platform limits](crate::tcp_fingerprint). This does not guarantee a JA4T match.
/// All fields are optional: `None` leaves the transport's setting unchanged.
/// In particular, the transport defaults to `TCP_NODELAY=true` even without
/// a fingerprint; other unset options retain their OS defaults.
///
/// # JA4T fields
///
/// The four core JA4T fields map directly to struct fields:
///
/// | JA4T Part | Field | Description |
/// |-----------|-------|-------------|
/// | A | [`window_size`](Self::window_size) | TCP Window Size in SYN |
/// | B | [`tcp_options`](Self::tcp_options) | TCP options order (kernel-determined) |
/// | C | [`mss`](Self::mss) | Maximum Segment Size |
/// | D | [`window_scale`](Self::window_scale) | Window Scale factor |
///
/// # Example
///
/// ```rust,no_run
/// use lkrequest::{Client, TcpFingerprint};
/// use lktls::profile::presets;
///
/// // Use a preset
/// let client = Client::builder()
///     .fingerprint(presets::chrome_144())
///     .tcp_fingerprint(TcpFingerprint::chrome())
///     .build();
///
/// // Or parse from a JA4T string
/// let fp = TcpFingerprint::from_ja4t("64240_2-4-8-1-3_1460_8").unwrap()
///     .with_ttl(128);
///
/// let client = Client::builder()
///     .fingerprint(presets::chrome_144())
///     .tcp_fingerprint(fp)
///     .build();
/// ```
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TcpFingerprint {
    // === JA4T Part A: Window Size ===
    /// Target TCP Window Size in the SYN packet (JA4T Part A).
    ///
    /// Common values:
    /// - `64240` — Windows 10/11
    /// - `65535` — macOS, iOS, Linux (common)
    /// - `29200` — Linux (some kernels)
    ///
    /// When set together with [`window_scale`](Self::window_scale), the
    /// `SO_RCVBUF` request is computed automatically to influence the kernel's
    /// choice, without guaranteeing either target value. Alone, this field
    /// does not change the socket. If [`recv_buf_size`](Self::recv_buf_size)
    /// is also set, it takes precedence as a raw override.
    pub window_size: Option<u32>,

    // === JA4T Part B: TCP Options ===
    /// TCP options in SYN packet order (JA4T Part B).
    ///
    /// **Note**: The actual options and their order are determined by the OS
    /// kernel TCP stack. This library does not apply this list to the socket,
    /// including toggling Timestamps or SACK. This field is used for:
    /// - JA4T string generation ([`to_ja4t()`](Self::to_ja4t))
    /// - Documentation of the target fingerprint
    /// - Validation against captured traffic
    ///
    /// See [`TcpOption`] for common OS-specific orderings.
    pub tcp_options: Option<Vec<TcpOption>>,

    // === JA4T Part C: Maximum Segment Size ===
    /// Maximum Segment Size (JA4T Part C).
    ///
    /// Standard value is `1460` (Ethernet MTU 1500 minus 40 bytes of IP+TCP
    /// headers). Lower values like `1380` suggest VPN/tunnel overhead.
    ///
    /// **Platform support**: applied via `TCP_MAXSEG` setsockopt on Linux.
    /// The Linux kernel still imposes range and MTU limits. On Windows/macOS
    /// this library does not apply the field; it is stored for JA4T purposes
    /// only. This is an implementation limit, not a claim that those operating
    /// systems expose no MSS configuration APIs.
    pub mss: Option<u32>,

    // === JA4T Part D: Window Scale ===
    /// Window Scale factor (JA4T Part D).
    ///
    /// After negotiation, scales TCP window fields by `2^window_scale`.
    /// The window field in the SYN itself is not scaled.
    ///
    /// Common values:
    /// - `8` — Windows 10/11, Linux (common)
    /// - `7` — Linux (some configurations)
    /// - `6` — macOS/iOS
    ///
    /// When both `window_size` and `window_scale` are set, we derive a
    /// `SO_RCVBUF` request. The kernel chooses the actual scale; it need not
    /// match this value. Alone, this field does not change the socket.
    pub window_scale: Option<u8>,

    // === Additional TCP parameters (not in JA4T string) ===
    /// IPv4 Time-To-Live, or IPv6 unicast Hop Limit.
    ///
    /// Typical values: `64` (Linux/macOS), `128` (Windows).
    /// While not part of the JA4T string, TTL is a key OS fingerprint
    /// dimension checked by some WAFs.
    pub ttl: Option<u32>,

    /// Raw TCP receive buffer size override (`SO_RCVBUF`).
    ///
    /// When set, this value is used directly as `SO_RCVBUF`, bypassing
    /// the automatic calculation from `window_size` + `window_scale`.
    ///
    /// The OS may limit or adjust the requested size. This does not directly
    /// set the SYN window or its scale. On Linux, explicitly setting the
    /// receive buffer also disables receive-buffer autotuning for the socket.
    pub recv_buf_size: Option<u32>,

    /// TCP send buffer size (`SO_SNDBUF`).
    pub send_buf_size: Option<u32>,

    /// Disable Nagle's algorithm (`TCP_NODELAY`).
    ///
    /// Browsers typically enable `TCP_NODELAY` (set to `true`).
    pub tcp_nodelay: Option<bool>,

    /// TCP keep-alive configuration.
    pub keepalive: Option<TcpKeepalive>,
}

// ---------------------------------------------------------------------------
// JA4T parsing / formatting
// ---------------------------------------------------------------------------

/// Error returned when parsing a JA4T string fails.
#[derive(Debug, Clone)]
pub struct Ja4tParseError {
    pub message: String,
}

impl fmt::Display for Ja4tParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JA4T parse error: {}", self.message)
    }
}

impl std::error::Error for Ja4tParseError {}

impl TcpFingerprint {
    // -------------------------------------------------------------------
    // JA4T string operations
    // -------------------------------------------------------------------

    /// Parse a target JA4T string into configuration fields.
    ///
    /// Parsing does not check whether the platform can emit that fingerprint.
    /// TTL, buffers, Nagle and keepalive are not encoded in the string.
    ///
    /// Format: `{window_size}_{tcp_options}_{mss}_{window_scale}`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use lkrequest::TcpFingerprint;
    ///
    /// // A target with a Linux-style options order
    /// let fp = TcpFingerprint::from_ja4t("64240_2-4-8-1-3_1460_8").unwrap();
    /// assert_eq!(fp.window_size, Some(64240));
    /// assert_eq!(fp.mss, Some(1460));
    /// assert_eq!(fp.window_scale, Some(8));
    ///
    /// // Safari on macOS
    /// let fp = TcpFingerprint::from_ja4t("65535_2-1-3-1-1-8-4-0_1460_6").unwrap();
    /// assert_eq!(fp.window_size, Some(65535));
    /// assert_eq!(fp.window_scale, Some(6));
    /// ```
    pub fn from_ja4t(s: &str) -> Result<Self, Ja4tParseError> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() != 4 {
            return Err(Ja4tParseError {
                message: format!(
                    "expected 4 underscore-separated parts, got {}. Format: window_size_options_mss_scale",
                    parts.len()
                ),
            });
        }

        // Part A: Window Size
        let window_size: u32 = parts[0].parse().map_err(|e| Ja4tParseError {
            message: format!("invalid window_size '{}': {}", parts[0], e),
        })?;

        // Part B: TCP Options (dash-separated kind numbers)
        let tcp_options: Vec<TcpOption> = parts[1]
            .split('-')
            .map(|s| {
                let kind: u8 = s.parse().map_err(|e| Ja4tParseError {
                    message: format!("invalid TCP option kind '{}': {}", s, e),
                })?;
                TcpOption::from_kind(kind).ok_or_else(|| Ja4tParseError {
                    message: format!("unknown TCP option kind: {}", kind),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Part C: MSS
        let mss: u32 = parts[2].parse().map_err(|e| Ja4tParseError {
            message: format!("invalid MSS '{}': {}", parts[2], e),
        })?;

        // Part D: Window Scale
        let window_scale: u8 = parts[3].parse().map_err(|e| Ja4tParseError {
            message: format!("invalid window_scale '{}': {}", parts[3], e),
        })?;

        Ok(Self {
            window_size: Some(window_size),
            tcp_options: Some(tcp_options),
            mss: Some(mss),
            window_scale: Some(window_scale),
            // Non-JA4T fields left as None
            ttl: None,
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: None,
            keepalive: None,
        })
    }

    /// Format the configured target fields as a JA4T string.
    ///
    /// This does not inspect a socket or captured traffic. Stored-only and
    /// kernel-adjusted fields can differ from the actual SYN fingerprint.
    ///
    /// Returns `None` if any of the four JA4T parts is not set.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lkrequest::TcpFingerprint;
    ///
    /// let fp = TcpFingerprint::chrome_win();
    /// assert_eq!(fp.to_ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
    /// ```
    pub fn to_ja4t(&self) -> Option<String> {
        let ws = self.window_size?;
        let opts = self.tcp_options.as_ref()?;
        let mss = self.mss?;
        let scale = self.window_scale?;

        let opts_str: String = opts
            .iter()
            .map(|o| o.kind().to_string())
            .collect::<Vec<_>>()
            .join("-");

        Some(format!("{}_{}_{}_{}", ws, opts_str, mss, scale))
    }

    // -------------------------------------------------------------------
    // Builder-style setters (chainable after from_ja4t or preset)
    // -------------------------------------------------------------------

    /// Set the IP TTL.
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set TCP_NODELAY.
    pub fn with_tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.tcp_nodelay = Some(nodelay);
        self
    }

    /// Set the window size (JA4T Part A).
    pub fn with_window_size(mut self, size: u32) -> Self {
        self.window_size = Some(size);
        self
    }

    /// Set the window scale factor (JA4T Part D).
    pub fn with_window_scale(mut self, scale: u8) -> Self {
        self.window_scale = Some(scale);
        self
    }

    /// Set the MSS (JA4T Part C).
    pub fn with_mss(mut self, mss: u32) -> Self {
        self.mss = Some(mss);
        self
    }

    /// Set the TCP options (JA4T Part B).
    pub fn with_tcp_options(mut self, options: Vec<TcpOption>) -> Self {
        self.tcp_options = Some(options);
        self
    }

    /// Override the raw receive buffer size (`SO_RCVBUF`).
    pub fn with_recv_buf_size(mut self, size: u32) -> Self {
        self.recv_buf_size = Some(size);
        self
    }

    /// Set TCP send buffer size (`SO_SNDBUF`).
    pub fn with_send_buf_size(mut self, size: u32) -> Self {
        self.send_buf_size = Some(size);
        self
    }

    /// Set TCP keep-alive configuration.
    pub fn with_keepalive(mut self, keepalive: TcpKeepalive) -> Self {
        self.keepalive = Some(keepalive);
        self
    }

    // -------------------------------------------------------------------
    // Presets
    // -------------------------------------------------------------------

    /// No TCP fingerprint overrides; the transport still enables TCP_NODELAY.
    pub fn none() -> Self {
        Self::default()
    }

    /// Chrome on Windows TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 64240_2-1-3-1-1-4_1460_8
    /// TTL:  128
    /// ```
    pub fn chrome_win() -> Self {
        Self {
            window_size: Some(64240),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::SACKPermitted,
            ]),
            mss: Some(1460),
            window_scale: Some(8),
            ttl: Some(128),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Chrome on Linux TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-4-8-1-3_1460_7
    /// TTL:  64
    /// ```
    pub fn chrome_linux() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::SACKPermitted,
                TcpOption::Timestamps,
                TcpOption::NOP,
                TcpOption::WindowScale,
            ]),
            mss: Some(1460),
            window_scale: Some(7),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Chrome on macOS TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-8-4-0_1460_6
    /// TTL:  64
    /// ```
    pub fn chrome_macos() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::Timestamps,
                TcpOption::SACKPermitted,
                TcpOption::EOL,
            ]),
            mss: Some(1460),
            window_scale: Some(6),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Chrome TCP target selected by the compile-time OS, without wire validation.
    pub fn chrome() -> Self {
        if cfg!(target_os = "windows") {
            Self::chrome_win()
        } else if cfg!(target_os = "macos") {
            Self::chrome_macos()
        } else {
            Self::chrome_linux()
        }
    }

    /// Firefox on Windows TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-4_1460_8
    /// TTL:  128
    /// ```
    pub fn firefox_win() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::SACKPermitted,
            ]),
            mss: Some(1460),
            window_scale: Some(8),
            ttl: Some(128),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Firefox on Linux TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-4-8-1-3_1460_7
    /// TTL:  64
    /// ```
    pub fn firefox_linux() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::SACKPermitted,
                TcpOption::Timestamps,
                TcpOption::NOP,
                TcpOption::WindowScale,
            ]),
            mss: Some(1460),
            window_scale: Some(7),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Firefox on macOS TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-8-4-0_1460_6
    /// TTL:  64
    /// ```
    pub fn firefox_macos() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::Timestamps,
                TcpOption::SACKPermitted,
                TcpOption::EOL,
            ]),
            mss: Some(1460),
            window_scale: Some(6),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Firefox TCP target selected by the compile-time OS, without wire validation.
    pub fn firefox() -> Self {
        if cfg!(target_os = "windows") {
            Self::firefox_win()
        } else if cfg!(target_os = "macos") {
            Self::firefox_macos()
        } else {
            Self::firefox_linux()
        }
    }

    /// Safari on macOS TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-8-4-0_1460_6
    /// TTL:  64
    /// ```
    pub fn safari() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::Timestamps,
                TcpOption::SACKPermitted,
                TcpOption::EOL,
            ]),
            mss: Some(1460),
            window_scale: Some(6),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Safari on iOS TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-8-4-0_1460_6
    /// TTL:  64
    /// ```
    pub fn safari_ios() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::Timestamps,
                TcpOption::SACKPermitted,
                TcpOption::EOL,
            ]),
            mss: Some(1460),
            window_scale: Some(6),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    // -------------------------------------------------------------------
    // Socket application
    // -------------------------------------------------------------------

    /// Compute the `SO_RCVBUF` value from `window_size` and `window_scale`.
    ///
    /// Derive a receive-buffer request from the target fields:
    ///
    /// ```text
    /// target = window_size * 2^window_scale
    /// ```
    ///
    /// On Linux, the kernel internally doubles `SO_RCVBUF` for bookkeeping
    /// overhead, so we halve the target value on Linux. This heuristic does
    /// not guarantee the requested SYN window or scale after kernel limits.
    fn compute_recv_buf(&self) -> Option<u32> {
        let ws = self.window_size?;
        let scale = self.window_scale?;

        // Target receive buffer: window_size * 2^scale
        let target = (ws as u64) << (scale as u64);

        // On Linux, kernel doubles SO_RCVBUF internally, so set half
        #[cfg(target_os = "linux")]
        let adjusted = (target / 2).min(u32::MAX as u64) as u32;

        #[cfg(not(target_os = "linux"))]
        let adjusted = target.min(u32::MAX as u64) as u32;

        Some(adjusted)
    }

    /// Apply this fingerprint to a `socket2::Socket` before connecting.
    ///
    /// Socket-setting failures are returned to the caller. Stored-only fields
    /// are skipped: TCP options on all platforms and MSS outside Linux.
    /// Successful application does not verify the outgoing SYN fingerprint.
    pub(crate) fn apply_to_socket(
        &self,
        socket: &socket2::Socket,
        is_ipv6: bool,
    ) -> std::io::Result<()> {
        // --- TTL / Hop Limit ---
        if let Some(ttl) = self.ttl {
            if is_ipv6 {
                socket.set_unicast_hops_v6(ttl)?;
            } else {
                socket.set_ttl_v4(ttl)?;
            }
        }

        // --- Receive buffer (Window Size + Window Scale) ---
        // Priority: recv_buf_size (raw override) > computed from window_size + window_scale
        if let Some(size) = self.recv_buf_size {
            socket.set_recv_buffer_size(size as usize)?;
        } else if let Some(computed) = self.compute_recv_buf() {
            socket.set_recv_buffer_size(computed as usize)?;
        }

        // --- Send buffer ---
        if let Some(size) = self.send_buf_size {
            socket.set_send_buffer_size(size as usize)?;
        }

        // --- TCP_NODELAY ---
        if let Some(nodelay) = self.tcp_nodelay {
            socket.set_tcp_nodelay(nodelay)?;
        }

        // --- MSS (TCP_MAXSEG) — Linux only ---
        #[cfg(target_os = "linux")]
        if let Some(mss) = self.mss {
            apply_mss_linux(socket, mss)?;
        }

        #[cfg(not(target_os = "linux"))]
        if self.mss.is_some() {
            tracing::trace!(
                mss = self.mss,
                "tcp_fingerprint: MSS stored for JA4T but not applied (Linux only)"
            );
        }

        // --- Keep-alive ---
        if let Some(ref ka) = self.keepalive {
            if ka.enabled {
                let mut keepalive = socket2::TcpKeepalive::new();
                if let Some(idle) = ka.idle {
                    keepalive = keepalive.with_time(idle);
                }
                if let Some(interval) = ka.interval {
                    keepalive = keepalive.with_interval(interval);
                }
                socket.set_tcp_keepalive(&keepalive)?;
            }
        }

        tracing::trace!(
            ja4t = ?self.to_ja4t(),
            ttl = ?self.ttl,
            "tcp_fingerprint: applied to socket"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Platform-specific: MSS on Linux
// ---------------------------------------------------------------------------

/// Apply MSS via `setsockopt(IPPROTO_TCP, TCP_MAXSEG)` on Linux.
///
/// This must be called **before** `connect()` to influence the MSS option
/// in the outgoing SYN packet.
#[cfg(target_os = "linux")]
fn apply_mss_linux(socket: &socket2::Socket, mss: u32) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let mss_val: libc::c_int = mss as libc::c_int;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &mss_val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(mss, error = %err, "tcp_fingerprint: failed to set TCP_MAXSEG");
        return Err(err);
    }

    tracing::trace!(mss, "tcp_fingerprint: TCP_MAXSEG applied");
    Ok(())
}

// ---------------------------------------------------------------------------
// connect_tcp_with_fingerprint
// ---------------------------------------------------------------------------

/// Create a connected TCP stream with optional TCP fingerprint applied.
///
/// Uses `socket2::Socket` for low-level socket configuration, then converts
/// to a `tokio::net::TcpStream` for async use.
///
/// DNS resolution is performed via the provided [`crate::dns::DnsResolver`].
pub(crate) async fn connect_tcp_with_fingerprint(
    host: &str,
    port: u16,
    fingerprint: Option<&TcpFingerprint>,
    resolver: &dyn crate::dns::DnsResolver,
    connect_timeout: Option<Duration>,
    connection_budget: Option<crate::connection_pool::ConnectionBudget>,
    execution: &ConnectionExecution,
) -> std::io::Result<tokio::net::TcpStream> {
    let dns_started = std::time::Instant::now();
    let resolved = resolver.resolve(host, port).await;
    crate::diagnostics::record_dns_ms(dns_started.elapsed().as_millis() as u64);
    let addresses = interleave_address_families(resolved?);
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("DNS resolution returned no addresses for {host}"),
        ));
    }

    dial_tcp_addresses(
        host,
        port,
        addresses,
        fingerprint.cloned(),
        connect_timeout,
        connection_budget,
        execution,
        |address, fingerprint, execution| async move {
            dial_tcp_address(address, fingerprint.as_ref(), &execution).await
        },
    )
    .await
}

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const MAX_SERIAL_ATTEMPT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialAttemptKind {
    Primary,
    Speculative,
}

struct DialAttemptResult {
    kind: DialAttemptKind,
    address: std::net::SocketAddr,
    elapsed: Duration,
    result: std::io::Result<tokio::net::TcpStream>,
    _speculative_permit: Option<crate::connection_pool::ConnectionPermit>,
}

#[allow(clippy::too_many_arguments)]
async fn dial_tcp_addresses<D, F>(
    host: &str,
    port: u16,
    addresses: Vec<std::net::SocketAddr>,
    fingerprint: Option<TcpFingerprint>,
    connect_timeout: Option<Duration>,
    connection_budget: Option<crate::connection_pool::ConnectionBudget>,
    execution: &ConnectionExecution,
    dial: D,
) -> std::io::Result<tokio::net::TcpStream>
where
    D: Fn(std::net::SocketAddr, Option<TcpFingerprint>, ConnectionExecution) -> F
        + Clone
        + Send
        + 'static,
    F: std::future::Future<Output = std::io::Result<tokio::net::TcpStream>> + Send + 'static,
{
    let deadline =
        connect_timeout.and_then(|timeout| tokio::time::Instant::now().checked_add(timeout));
    let mut attempts = tokio::task::JoinSet::new();
    let mut next_address = 0usize;
    let mut primary_active = false;
    let mut speculative_active = false;
    let mut primary_started = None;
    let mut primary_cutoff = None;
    let mut primary_abort = None;
    let mut primary_address = None;
    let mut errors = Vec::new();
    let mut admission_error = None;

    loop {
        if admission_error.is_none() && !primary_active && next_address < addresses.len() {
            let address = addresses[next_address];
            next_address += 1;
            let started = tokio::time::Instant::now();
            let remaining_candidates = addresses.len() - next_address + 1;
            let remaining = deadline
                .map(|deadline| deadline.saturating_duration_since(started))
                .unwrap_or(Duration::MAX);
            let fair_share = remaining / u32::try_from(remaining_candidates).unwrap_or(u32::MAX);
            let serial_window = fair_share.max(HAPPY_EYEBALLS_DELAY).min(MAX_SERIAL_ATTEMPT);

            primary_started = Some(started);
            primary_cutoff = Some(started + serial_window.min(remaining));
            primary_active = true;
            primary_address = Some(address);
            primary_abort = Some(spawn_dial_attempt(
                &mut attempts,
                DialAttemptKind::Primary,
                address,
                fingerprint.clone(),
                None,
                execution.clone(),
                dial.clone(),
            ));
        }

        if !primary_active
            && !speculative_active
            && (admission_error.is_some() || next_address >= addresses.len())
        {
            break;
        }

        let now = tokio::time::Instant::now();
        if deadline.is_some_and(|deadline| now >= deadline) {
            attempts.abort_all();
            while attempts.join_next().await.is_some() {}
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "TCP connect to {host}:{port} timed out after {}",
                    crate::timeout::display_duration(connect_timeout)
                ),
            ));
        }

        let fallback_at = primary_started.map(|started| started + HAPPY_EYEBALLS_DELAY);
        let next_timer = [deadline, fallback_at, primary_cutoff]
            .into_iter()
            .flatten()
            .filter(|instant| *instant > now)
            .min();

        tokio::select! {
            joined = attempts.join_next(), if !attempts.is_empty() => {
                let Some(joined) = joined else { continue };
                let attempt = joined.map_err(|error| {
                    std::io::Error::other(format!("TCP dial task failed: {error}"))
                })?;

                match attempt.kind {
                    DialAttemptKind::Primary => {
                        primary_active = false;
                        primary_started = None;
                        primary_cutoff = None;
                        primary_abort = None;
                        primary_address = None;
                    }
                    DialAttemptKind::Speculative => speculative_active = false,
                }

                match attempt.result {
                    Ok(stream) => {
                        attempts.abort_all();
                        while attempts.join_next().await.is_some() {}
                        drop(attempt._speculative_permit);
                        crate::diagnostics::record_tcp_ms(attempt.elapsed.as_millis() as u64);
                        crate::diagnostics::record_remote_addr(attempt.address.to_string());
                        return Ok(stream);
                    }
                    Err(error) => match take_connect_execution_io(error) {
                        Ok(error) => {
                            // Admission closes only new candidates. An already
                            // started competitor keeps its original deadline.
                            admission_error = Some(error);
                            primary_started = None;
                            primary_cutoff = None;
                        }
                        Err(error) => {
                            tracing::debug!(
                                address = %attempt.address,
                                error = %error,
                                attempt = ?attempt.kind,
                                "tcp.connect_address_failed"
                            );
                            errors.push((attempt.address, error));
                            if attempt.kind == DialAttemptKind::Speculative
                                && admission_error.is_none()
                                && primary_active
                                && next_address < addresses.len()
                            {
                                let restarted = tokio::time::Instant::now();
                                let remaining_candidates = addresses.len() - next_address + 1;
                                let remaining = deadline.map(|deadline| deadline.saturating_duration_since(restarted))
                                    .unwrap_or(Duration::MAX);
                                let fair_share = remaining
                                    / u32::try_from(remaining_candidates).unwrap_or(u32::MAX);
                                let serial_window = fair_share
                                    .max(HAPPY_EYEBALLS_DELAY)
                                    .min(MAX_SERIAL_ATTEMPT);
                                primary_started = Some(restarted);
                                primary_cutoff = Some(restarted + serial_window.min(remaining));
                            }
                        }
                    },
                }
            }
            _ = async {
                match next_timer {
                    Some(timer) => tokio::time::sleep_until(timer).await,
                    None => std::future::pending().await,
                }
            } => {
                let now = tokio::time::Instant::now();
                if deadline.is_some_and(|deadline| now >= deadline) {
                    continue;
                }

                let fallback_due = primary_active
                    && admission_error.is_none()
                    && !speculative_active
                    && next_address < addresses.len()
                    && fallback_at.is_some_and(|instant| now >= instant);

                if fallback_due {
                    let speculative_permit = match connection_budget.as_ref() {
                        Some(budget) => budget.try_reserve_speculative().map(Some),
                        None => Some(None),
                    };

                    if let Some(speculative_permit) = speculative_permit {
                        let address = addresses[next_address];
                        next_address += 1;
                        speculative_active = true;
                        primary_cutoff = None;
                        spawn_dial_attempt(
                            &mut attempts,
                            DialAttemptKind::Speculative,
                            address,
                            fingerprint.clone(),
                            speculative_permit,
                            execution.clone(),
                            dial.clone(),
                        );
                        continue;
                    }
                }

                let serial_cutoff_due = primary_active
                    && admission_error.is_none()
                    && !speculative_active
                    && next_address < addresses.len()
                    && primary_cutoff.is_some_and(|instant| now >= instant);
                if serial_cutoff_due {
                    if let Err(error) = execution.check_start_allowed() {
                        admission_error = Some(error);
                        primary_started = None;
                        primary_cutoff = None;
                        continue;
                    }
                    if let Some(abort) = primary_abort.take() {
                        abort.abort();
                    }
                    let _ = attempts.join_next().await;
                    primary_active = false;
                    primary_started = None;
                    primary_cutoff = None;
                    errors.push((
                        primary_address.take().expect("active primary has an address"),
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "address attempt exceeded its serial fallback window",
                        ),
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        if let Some(error) = admission_error {
            return Err(connect_execution_io(error));
        }
    }
    let last_kind = errors
        .last()
        .map(|(_, error)| error.kind())
        .unwrap_or(std::io::ErrorKind::AddrNotAvailable);
    let details = errors
        .iter()
        .map(|(address, error)| format!("{address}: {error}"))
        .collect::<Vec<_>>()
        .join("; ");
    let error = std::io::Error::new(
        last_kind,
        format!("TCP connect to {host}:{port} failed for all addresses: {details}"),
    );
    Err(match admission_error {
        Some(denied) => connect_execution_io(denied.with_connect_prior(Error::Io(error))),
        None => error,
    })
}

fn spawn_dial_attempt<D, F>(
    attempts: &mut tokio::task::JoinSet<DialAttemptResult>,
    kind: DialAttemptKind,
    address: std::net::SocketAddr,
    fingerprint: Option<TcpFingerprint>,
    speculative_permit: Option<crate::connection_pool::ConnectionPermit>,
    execution: ConnectionExecution,
    dial: D,
) -> tokio::task::AbortHandle
where
    D: Fn(std::net::SocketAddr, Option<TcpFingerprint>, ConnectionExecution) -> F + Send + 'static,
    F: std::future::Future<Output = std::io::Result<tokio::net::TcpStream>> + Send + 'static,
{
    attempts.spawn(async move {
        let started = std::time::Instant::now();
        let result = dial(address, fingerprint, execution).await;
        DialAttemptResult {
            kind,
            address,
            elapsed: started.elapsed(),
            result,
            _speculative_permit: speculative_permit,
        }
    })
}

async fn dial_tcp_address(
    socket_addr: std::net::SocketAddr,
    fingerprint: Option<&TcpFingerprint>,
    execution: &ConnectionExecution,
) -> std::io::Result<tokio::net::TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // Set non-blocking before connect (required for tokio)
    socket.set_nonblocking(true)?;

    // Interactive HTTP traffic benefits from disabling Nagle by default.
    // A configured fingerprint can still explicitly restore TCP_NODELAY=false.
    socket.set_tcp_nodelay(true)?;

    // Apply TCP fingerprint parameters BEFORE connect — this is critical
    // because TTL, window size, and MSS must be set before the SYN packet.
    let is_ipv6 = socket_addr.is_ipv6();
    if let Some(fp) = fingerprint {
        fp.apply_to_socket(&socket, is_ipv6)?;
    }

    // Initiate non-blocking connect
    let sock_addr = socket2::SockAddr::from(socket_addr);
    execution
        .commit_start("tcp")
        .map_err(connect_execution_io)?;
    match socket.connect(&sock_addr) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(connect_in_progress_code()) => {
            // Connection in progress — expected for non-blocking socket
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            // Some platforms return this for non-blocking connect-in-progress
        }
        Err(e) => return Err(e),
    }

    // Convert to tokio TcpStream and wait for connection
    let std_stream: std::net::TcpStream = socket.into();
    let stream = tokio::net::TcpStream::from_std(std_stream)?;

    // Wait for the connection to complete
    stream.writable().await?;

    // Check for connection errors
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    Ok(stream)
}

pub(crate) fn interleave_address_families(
    addresses: Vec<std::net::SocketAddr>,
) -> Vec<std::net::SocketAddr> {
    let Some(first) = addresses.first() else {
        return addresses;
    };
    let prefer_ipv6 = first.is_ipv6();
    let mut ipv4 = addresses.iter().copied().filter(|addr| addr.is_ipv4());
    let mut ipv6 = addresses.iter().copied().filter(|addr| addr.is_ipv6());
    let mut interleaved = Vec::with_capacity(addresses.len());

    loop {
        let preferred = if prefer_ipv6 {
            ipv6.next()
        } else {
            ipv4.next()
        };
        let fallback = if prefer_ipv6 {
            ipv4.next()
        } else {
            ipv6.next()
        };
        match (preferred, fallback) {
            (None, None) => break,
            (Some(address), None) | (None, Some(address)) => interleaved.push(address),
            (Some(preferred), Some(fallback)) => {
                interleaved.push(preferred);
                interleaved.push(fallback);
            }
        }
    }

    interleaved
}

/// Platform-specific "in progress" error code for non-blocking connect.
#[cfg(target_os = "windows")]
fn connect_in_progress_code() -> i32 {
    // WSAEWOULDBLOCK
    10035
}

#[cfg(not(target_os = "windows"))]
fn connect_in_progress_code() -> i32 {
    libc::EINPROGRESS
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn limited_execution(
        limit: u64,
    ) -> (
        crate::session::execution::RequestExecution,
        crate::session::execution::ExecutionGuard,
    ) {
        let limits = crate::AttemptLimits::default()
            .with_connect_attempts(limit)
            .resolve(None, crate::AttemptLimitScope::Client)
            .unwrap();
        crate::session::execution::RequestExecution::with_limits(
            crate::timeout::RequestTimeout::default(),
            Some(limits),
        )
    }

    #[derive(Debug)]
    struct StaticResolver {
        addresses: Vec<std::net::SocketAddr>,
    }

    #[async_trait::async_trait]
    impl crate::dns::DnsResolver for StaticResolver {
        async fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> std::io::Result<Vec<std::net::SocketAddr>> {
            Ok(self.addresses.clone())
        }
    }

    #[tokio::test]
    async fn connect_falls_back_when_first_dns_address_is_unreachable() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let resolver = StaticResolver {
            addresses: vec![
                std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), port),
                std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), port),
            ],
        };
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut pool = crate::connection_pool::ConnectionPool::with_max_total(1);
        let _primary_permit = pool
            .try_reserve_connection()
            .expect("primary dial reservation");
        let budget = pool.connection_budget();
        assert!(budget.try_reserve_speculative().is_none());
        let (execution, _guard) = ConnectionExecution::new();

        let stream = connect_tcp_with_fingerprint(
            "multi-address.test",
            port,
            None,
            &resolver,
            Some(Duration::from_secs(5)),
            Some(budget),
            &execution,
        )
        .await
        .expect("the IPv4 address should be tried after IPv6 fails");

        assert_eq!(
            stream.peer_addr().unwrap().ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn direct_tcp_defaults_to_nodelay() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let (execution, _guard) = ConnectionExecution::new();
        let stream = dial_tcp_address(address, None, &execution).await.unwrap();

        assert!(stream.nodelay().unwrap());
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn explicit_nodelay_false_overrides_transport_default() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let fingerprint = TcpFingerprint::default().with_tcp_nodelay(false);

        let (execution, _guard) = ConnectionExecution::new();
        let stream = dial_tcp_address(address, Some(&fingerprint), &execution)
            .await
            .unwrap();

        assert!(!stream.nodelay().unwrap());
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn zero_connect_limit_does_not_start_tcp() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (request, _guard) = limited_execution(0);
        let error = dial_tcp_address(listener.local_addr().unwrap(), None, &request.connection())
            .await
            .unwrap_err();
        assert!(take_connect_execution_io(error)
            .unwrap()
            .is_connect_attempt_denied());
        assert_eq!(request.snapshot_summary().connect_initiations(), 0);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn invalid_socket_ttl_costs_no_connect_attempt() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (request, _guard) = limited_execution(1);
        let fingerprint = TcpFingerprint::default().with_ttl(256);
        let error = dial_tcp_address(
            listener.local_addr().unwrap(),
            Some(&fingerprint),
            &request.connection(),
        )
        .await
        .expect_err("IPv4 TTL above 255 must fail during socket preparation");
        assert!(
            take_connect_execution_io(error).is_err(),
            "socket preparation must fail before admission is checked"
        );
        assert_eq!(request.snapshot_summary().connect_initiations(), 0);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn address_failover_charges_each_actual_tcp_start_and_preserves_first_failure() {
        for limit in [1, 2] {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let resolver = StaticResolver {
                addresses: vec![
                    std::net::SocketAddr::from(([127, 0, 0, 2], address.port())),
                    address,
                ],
            };
            let (request, _guard) = limited_execution(limit);
            let result = connect_tcp_with_fingerprint(
                "multi-address.test",
                address.port(),
                None,
                &resolver,
                Some(Duration::from_secs(5)),
                None,
                &request.connection(),
            )
            .await;
            assert_eq!(request.snapshot_summary().connect_initiations(), limit);
            if limit == 1 {
                let denial = take_connect_execution_io(result.unwrap_err()).unwrap();
                assert!(denial.is_connect_attempt_denied());
                let Error::Io(original) = denial.into_public_connect_error() else {
                    panic!("TCP failure must survive admission denial");
                };
                assert_eq!(original.kind(), std::io::ErrorKind::ConnectionRefused);
                assert_eq!(
                    listener.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            } else {
                assert_eq!(result.unwrap().peer_addr().unwrap(), address);
                listener.accept().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn empty_dns_result_costs_no_connect_attempt() {
        let (request, _guard) = limited_execution(0);
        let resolver = StaticResolver {
            addresses: Vec::new(),
        };
        let error = connect_tcp_with_fingerprint(
            "empty.test",
            80,
            None,
            &resolver,
            None,
            None,
            &request.connection(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrNotAvailable);
        assert_eq!(request.snapshot_summary().connect_initiations(), 0);
    }

    async fn denied_secondary_keeps_primary(
        primary_fails: bool,
        physical_limit: bool,
    ) -> (std::io::Result<tokio::net::TcpStream>, std::net::SocketAddr) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::sync::Notify;

        // Establish test data before pausing time; only dial completion and
        // admission are simulated, through the production scheduling loop.
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        tokio::time::pause();
        let stream = Arc::new(parking_lot::Mutex::new(Some(stream)));
        let calls = Arc::new(AtomicUsize::new(0));
        let primary_started = Arc::new(Notify::new());
        let secondary_denied = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let (request, _guard) = limited_execution(1);
        let execution = request.connection();
        let mut pool = crate::connection_pool::ConnectionPool::with_max_total(1);
        let _primary_slot = physical_limit.then(|| pool.try_reserve_connection().unwrap());
        let budget = physical_limit.then(|| pool.connection_budget());
        let dial = {
            let (stream, calls, primary_started, secondary_denied, release) = (
                stream.clone(),
                calls.clone(),
                primary_started.clone(),
                secondary_denied.clone(),
                release.clone(),
            );
            move |_address, _fingerprint, execution: ConnectionExecution| {
                let (stream, calls, primary_started, secondary_denied, release) = (
                    stream.clone(),
                    calls.clone(),
                    primary_started.clone(),
                    secondary_denied.clone(),
                    release.clone(),
                );
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if let Err(error) = execution.commit_start("tcp") {
                        secondary_denied.notify_one();
                        return Err(connect_execution_io(error));
                    }
                    primary_started.notify_one();
                    release.notified().await;
                    if primary_fails {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "admitted primary failed",
                        ))
                    } else {
                        Ok(stream.lock().take().unwrap())
                    }
                }
            }
        };
        let task = tokio::spawn(async move {
            dial_tcp_addresses(
                "fixture.test",
                address.port(),
                vec![address; 3],
                None,
                Some(Duration::from_secs(10)),
                budget,
                &execution,
                dial,
            )
            .await
        });
        primary_started.notified().await;
        tokio::time::advance(HAPPY_EYEBALLS_DELAY).await;
        if !physical_limit {
            secondary_denied.notified().await;
        }
        // Cross both fallback and serial-cutoff windows after the refusal.
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        assert!(!task.is_finished(), "admitted primary must remain active");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if physical_limit { 1 } else { 2 },
            "no third candidate after refusal"
        );
        release.notify_one();
        let result = task.await.unwrap();
        assert_eq!(request.snapshot_summary().connect_initiations(), 1);
        assert_eq!(
            request.snapshot_summary().denial_reason(),
            None,
            "loser denial is not sticky"
        );
        (result, address)
    }

    #[tokio::test]
    async fn denied_secondary_does_not_cancel_successful_primary() {
        let (result, address) = denied_secondary_keeps_primary(false, false).await;
        assert_eq!(result.unwrap().peer_addr().unwrap(), address);
    }

    #[tokio::test]
    async fn denied_secondary_preserves_admitted_primary_error() {
        let (result, _) = denied_secondary_keeps_primary(true, false).await;
        let error = take_connect_execution_io(result.unwrap_err()).unwrap();
        assert!(error.is_connect_attempt_denied());
        let Error::Io(original) = error.into_public_connect_error() else {
            panic!("real primary failure must survive denied secondary");
        };
        assert_eq!(original.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(original.to_string().contains("admitted primary failed"));
    }

    #[tokio::test]
    async fn exhausted_connect_budget_keeps_primary_when_physical_slot_blocks_speculation() {
        let (result, address) = denied_secondary_keeps_primary(false, true).await;
        assert_eq!(result.unwrap().peer_addr().unwrap(), address);
    }

    // -- JA4T parsing --

    #[test]
    fn parse_ja4t_chrome_win() {
        let fp = TcpFingerprint::from_ja4t("64240_2-1-3-1-1-4_1460_8").unwrap();
        assert_eq!(fp.window_size, Some(64240));
        assert_eq!(fp.mss, Some(1460));
        assert_eq!(fp.window_scale, Some(8));
        assert_eq!(
            fp.tcp_options,
            Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::SACKPermitted,
            ])
        );
    }

    #[test]
    fn parse_ja4t_linux() {
        let fp = TcpFingerprint::from_ja4t("65535_2-4-8-1-3_1460_7").unwrap();
        assert_eq!(fp.window_size, Some(65535));
        assert_eq!(fp.mss, Some(1460));
        assert_eq!(fp.window_scale, Some(7));
        assert_eq!(
            fp.tcp_options,
            Some(vec![
                TcpOption::MSS,
                TcpOption::SACKPermitted,
                TcpOption::Timestamps,
                TcpOption::NOP,
                TcpOption::WindowScale,
            ])
        );
    }

    #[test]
    fn parse_ja4t_macos() {
        let fp = TcpFingerprint::from_ja4t("65535_2-1-3-1-1-8-4-0_1460_6").unwrap();
        assert_eq!(fp.window_size, Some(65535));
        assert_eq!(fp.window_scale, Some(6));
        assert!(fp.tcp_options.as_ref().unwrap().contains(&TcpOption::EOL));
    }

    #[test]
    fn parse_ja4t_invalid_parts() {
        assert!(TcpFingerprint::from_ja4t("64240_2-4_1460").is_err());
        assert!(TcpFingerprint::from_ja4t("").is_err());
    }

    #[test]
    fn parse_ja4t_invalid_values() {
        assert!(TcpFingerprint::from_ja4t("abc_2-4_1460_8").is_err());
        assert!(TcpFingerprint::from_ja4t("64240_2-99_1460_8").is_err());
    }

    // -- JA4T formatting --

    #[test]
    fn format_ja4t_roundtrip() {
        let ja4t = "64240_2-1-3-1-1-4_1460_8";
        let fp = TcpFingerprint::from_ja4t(ja4t).unwrap();
        assert_eq!(fp.to_ja4t().unwrap(), ja4t);
    }

    #[test]
    fn format_ja4t_linux_roundtrip() {
        let ja4t = "65535_2-4-8-1-3_1460_7";
        let fp = TcpFingerprint::from_ja4t(ja4t).unwrap();
        assert_eq!(fp.to_ja4t().unwrap(), ja4t);
    }

    #[test]
    fn format_ja4t_none_when_missing() {
        let fp = TcpFingerprint::none();
        assert!(fp.to_ja4t().is_none());
    }

    // -- Presets --

    #[test]
    fn preset_chrome_win_ja4t() {
        let fp = TcpFingerprint::chrome_win();
        assert_eq!(fp.to_ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
        assert_eq!(fp.ttl, Some(128));
        assert_eq!(fp.tcp_nodelay, Some(true));
    }

    #[test]
    fn preset_chrome_linux_ja4t() {
        let fp = TcpFingerprint::chrome_linux();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-4-8-1-3_1460_7");
        assert_eq!(fp.ttl, Some(64));
    }

    #[test]
    fn preset_chrome_macos_ja4t() {
        let fp = TcpFingerprint::chrome_macos();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-1-3-1-1-8-4-0_1460_6");
        assert_eq!(fp.ttl, Some(64));
    }

    #[test]
    fn preset_firefox_win_ja4t() {
        let fp = TcpFingerprint::firefox_win();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-1-3-1-1-4_1460_8");
        assert_eq!(fp.ttl, Some(128));
    }

    #[test]
    fn preset_firefox_linux_ja4t() {
        let fp = TcpFingerprint::firefox_linux();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-4-8-1-3_1460_7");
        assert_eq!(fp.ttl, Some(64));
    }

    #[test]
    fn preset_safari_ja4t() {
        let fp = TcpFingerprint::safari();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-1-3-1-1-8-4-0_1460_6");
        assert_eq!(fp.ttl, Some(64));
    }

    #[test]
    fn preset_none() {
        let fp = TcpFingerprint::none();
        assert!(fp.ttl.is_none());
        assert!(fp.window_size.is_none());
        assert!(fp.tcp_nodelay.is_none());
        assert!(fp.to_ja4t().is_none());
    }

    // -- Builder chain --

    #[test]
    fn builder_chain_from_ja4t() {
        let fp = TcpFingerprint::from_ja4t("64240_2-1-3-1-1-4_1460_8")
            .unwrap()
            .with_ttl(128)
            .with_tcp_nodelay(true);

        assert_eq!(fp.ttl, Some(128));
        assert_eq!(fp.tcp_nodelay, Some(true));
        assert_eq!(fp.to_ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
    }

    #[test]
    fn builder_chain_individual_fields() {
        let fp = TcpFingerprint::none()
            .with_window_size(64240)
            .with_window_scale(8)
            .with_mss(1460)
            .with_tcp_options(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::SACKPermitted,
            ])
            .with_ttl(128);

        assert_eq!(fp.to_ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
    }

    // -- Recv buffer computation --

    #[test]
    fn compute_recv_buf_from_window() {
        let fp = TcpFingerprint::none()
            .with_window_size(64240)
            .with_window_scale(8);

        let computed = fp.compute_recv_buf().unwrap();

        // 64240 * 2^8 = 16,445,440
        #[cfg(target_os = "linux")]
        assert_eq!(computed, 16_445_440 / 2);

        #[cfg(not(target_os = "linux"))]
        assert_eq!(computed, 16_445_440);
    }

    #[test]
    fn compute_recv_buf_none_when_missing() {
        let fp = TcpFingerprint::none().with_window_size(64240);
        // window_scale is None, so compute_recv_buf returns None
        assert!(fp.compute_recv_buf().is_none());
    }

    // -- TcpOption --

    #[test]
    fn tcp_option_from_kind() {
        assert_eq!(TcpOption::from_kind(0), Some(TcpOption::EOL));
        assert_eq!(TcpOption::from_kind(1), Some(TcpOption::NOP));
        assert_eq!(TcpOption::from_kind(2), Some(TcpOption::MSS));
        assert_eq!(TcpOption::from_kind(3), Some(TcpOption::WindowScale));
        assert_eq!(TcpOption::from_kind(4), Some(TcpOption::SACKPermitted));
        assert_eq!(TcpOption::from_kind(8), Some(TcpOption::Timestamps));
        assert_eq!(TcpOption::from_kind(99), None);
    }

    #[test]
    fn tcp_option_kind_roundtrip() {
        for kind in [0u8, 1, 2, 3, 4, 8] {
            let opt = TcpOption::from_kind(kind).unwrap();
            assert_eq!(opt.kind(), kind);
        }
    }
}
