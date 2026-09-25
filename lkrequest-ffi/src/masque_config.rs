//! MASQUE outer-connection configuration handles (`lk_masque_config_*`).
//!
//! A `masque://` proxy URL says where the proxy is; it cannot say what the hop
//! *to* the proxy should trust. That hop is an ordinary HTTP/3 connection with
//! ordinary TLS, and a self-hosted or vendor-issued MASQUE deployment is
//! normally fronted by a private CA — so without a seam for trust anchors a C
//! caller could reach such a proxy for requests only by luck, and the proxy
//! pool's tunnel probe would fail its handshake and feed a *healthy* proxy to
//! the blacklist. That false negative is what this handle exists to fix.
//!
//! One handle covers both consumers, because they want the same answer:
//!
//! - [`lk_client_builder_set_masque_config`](crate::lk_client_builder_set_masque_config)
//!   — how requests build the outer connection
//!   ([`ClientBuilder::masque`](lkrequest::client::ClientBuilder::masque)).
//! - `lk_proxy_pool_builder_set_masque_tunnel_probe` /
//!   `lk_session_pool_builder_set_masque_tunnel_probe` — how the health check's
//!   probe builds it
//!   ([`HealthCheckConfig::masque_outer_config`](lkrequest::proxy_pool::HealthCheckConfig::masque_outer_config)).
//!
//! Both *copy* the settings out of the handle, so one handle can feed both and
//! is freed exactly once by the caller.
//!
//! ## What is not here
//!
//! `MasqueOuterConfig::verify` — the switch that turns off certificate
//! verification on the hop to the proxy — is **Rust-only** and has no entry
//! point here, by design. See `README.md` ("MASQUE outer configuration") for
//! the reasoning. Everything a private-CA deployment needs is reachable
//! without it: add the CA (DER or PEM), drop the OS store, and override the
//! certificate name if the proxy is addressed by something its certificate
//! does not cover.
//!
//! `bind_addr`, `alpn` and `inbox_depth` are not exposed either — not for
//! safety reasons, just for want of a caller. They can be added later without
//! disturbing anything, which is exactly what `MasqueOuterConfig` being
//! `#[non_exhaustive]` buys.
//!
//! ## Without the `masque` feature
//!
//! Every symbol below still exists, so the generated header and the ABI do not
//! change shape with the feature. `lk_masque_config_new` then returns
//! `LK_ERR`, the way `lk_proxy_config_parse` already refuses a `masque://`
//! URL. Since no handle can be created, the setters and consumers have nothing
//! valid to be called with and refuse in the same way.

// Every entry point here shares one body shape across the `masque` feature:
// `catch_status(.., || unsafe { .. })`, with the handle helpers inside. Without
// the feature those bodies shrink to "report the missing feature", and the
// `unsafe` block has nothing left to do — one allow is cheaper than two
// spellings of every function.
#![cfg_attr(not(feature = "masque"), allow(unused_unsafe))]

use std::ffi::c_char;

use crate::abi::lk_status_t;
use crate::error::FfiError;
use crate::handles::lk_masque_config_t;
use crate::panic::{catch_status, catch_value, null_error_out};

#[cfg(feature = "masque")]
use crate::conv::{read_bytes, read_string_parts};
#[cfg(feature = "masque")]
use crate::handles::{
    box_into_handle, handle_drop, require_handle, require_handle_mut, MasqueConfigHandle,
};

/// The error a build without the `masque` feature reports from every entry
/// point in this module.
#[cfg(not(feature = "masque"))]
fn masque_unavailable() -> FfiError {
    FfiError::invalid_config(
        "MASQUE support is not compiled in; rebuild lkrequest-ffi with the `masque` feature",
    )
}

/// Borrow the settings behind a handle, for the consumers in `client.rs` and
/// the pool builders.
#[cfg(feature = "masque")]
pub(crate) unsafe fn masque_config_ref(
    config: *const lk_masque_config_t,
) -> Result<&'static lkrequest::proxy::MasqueOuterConfig, FfiError> {
    let handle = require_handle::<MasqueConfigHandle, lk_masque_config_t>(config.cast_mut())?;
    Ok(&handle.config)
}

/// Create MASQUE outer-connection settings at their defaults.
///
/// The defaults are the Rust ones: verify the proxy's certificate against the
/// operating system's trust store, derive the certificate name from the proxy
/// URL, retire a tunnel idle for 120s, and carry at most 256 tunnels per outer
/// connection. A public-CA proxy needs none of the setters below.
///
/// Returns `LK_OK` and writes the handle to `out_config`; free it with
/// `lk_masque_config_free`. Returns `LK_ERR` and leaves `out_config` null if
/// this library was built without the `masque` feature.
#[no_mangle]
pub extern "C" fn lk_masque_config_new(out_config: *mut *mut lk_masque_config_t) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        if out_config.is_null() {
            return Err(FfiError::invalid_argument("out_config is null"));
        }
        *out_config = std::ptr::null_mut();

        #[cfg(feature = "masque")]
        {
            *out_config = box_into_handle::<MasqueConfigHandle, lk_masque_config_t>(
                MasqueConfigHandle::default(),
            );
            Ok(())
        }

        #[cfg(not(feature = "masque"))]
        Err(masque_unavailable())
    })
}

/// Append one trust anchor, in DER form, for the hop to the MASQUE proxy.
///
/// The counterpart of
/// [`MasqueOuterConfig::extra_roots`](lkrequest::proxy::MasqueOuterConfig::extra_roots)
/// and of `ClientBuilder::masque_add_ca_cert_der`. Can be called repeatedly;
/// each call appends.
///
/// This is **not** `lk_client_builder_add_ca_cert_memory` /
/// `lk_client_builder_add_ca_cert_file`: those trust a CA for the origin the
/// request is aimed at, this one for the proxy hop. They are separate on purpose, so a CA used by both must be handed to
/// both.
///
/// The bytes are copied. They are parsed as a trust anchor when the outer
/// connection is configured, so invalid DER surfaces on the first request (or
/// probe) through a `masque://` proxy rather than here — use
/// `lk_masque_config_add_ca_certs_pem` if you want the input validated up
/// front.
#[no_mangle]
pub extern "C" fn lk_masque_config_add_ca_cert_der(
    config: *mut lk_masque_config_t,
    der_ptr: *const u8,
    der_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        #[cfg(feature = "masque")]
        {
            let handle = require_handle_mut::<MasqueConfigHandle, lk_masque_config_t>(config)?;
            let der = read_bytes(der_ptr, der_len, "MASQUE CA certificate DER")?;
            if der.is_empty() {
                return Err(FfiError::invalid_config(
                    "MASQUE CA certificate DER is empty",
                ));
            }
            handle
                .config
                .extra_roots
                .push(rustls_pki_types::CertificateDer::from(der));
            Ok(())
        }

        #[cfg(not(feature = "masque"))]
        {
            let _ = (config, der_ptr, der_len);
            Err(masque_unavailable())
        }
    })
}

/// Append every certificate in a PEM bundle as a trust anchor for the hop to
/// the MASQUE proxy, and report how many were added through `out_added`
/// (optional; pass `NULL` to ignore the count).
///
/// The entry point to reach for: a private CA is normally distributed as PEM.
/// Delegates to
/// [`MasqueOuterConfig::add_ca_certs_pem`](lkrequest::proxy::MasqueOuterConfig::add_ca_certs_pem),
/// so a bundle of several certificates is accepted and non-certificate PEM
/// sections (a private key in the same file, say) are skipped.
///
/// Returns `LK_ERR` if a PEM section is malformed or if the
/// input holds no certificate at all — the second case being the one that
/// matters, because a path typo or a DER file passed here by mistake would
/// otherwise leave the trust store silently unchanged and the proxy verified
/// against whatever else happened to be trusted. Nothing is appended when this
/// fails, so a half-loaded trust store is not a state to reason about.
///
/// Note this takes the PEM *bytes*, not a path.
#[no_mangle]
pub extern "C" fn lk_masque_config_add_ca_certs_pem(
    config: *mut lk_masque_config_t,
    pem_ptr: *const c_char,
    pem_len: usize,
    out_added: *mut usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        #[cfg(feature = "masque")]
        {
            if !out_added.is_null() {
                *out_added = 0;
            }
            let handle = require_handle_mut::<MasqueConfigHandle, lk_masque_config_t>(config)?;
            let pem = read_bytes(pem_ptr.cast::<u8>(), pem_len, "MASQUE CA certificate PEM")?;
            let added = handle
                .config
                .add_ca_certs_pem(&pem)
                .map_err(FfiError::from_lkrequest)?;
            if !out_added.is_null() {
                *out_added = added;
            }
            Ok(())
        }

        #[cfg(not(feature = "masque"))]
        {
            let _ = (config, pem_ptr, pem_len);
            if !out_added.is_null() {
                *out_added = 0;
            }
            Err(masque_unavailable())
        }
    })
}

/// Trust the operating system's certificate store on the hop to the MASQUE
/// proxy. **Default: enabled.**
///
/// Pass `false` for a proxy behind a private CA: the outer connection then
/// verifies against the anchors added above and nothing else, so an unrelated
/// public CA cannot vouch for something answering on the proxy's address.
///
/// Disabling it with no anchors added is rejected when the outer connection is
/// built — there would be nothing left to verify against — rather than
/// silently accepting anything.
#[no_mangle]
pub extern "C" fn lk_masque_config_set_use_native_certs(
    config: *mut lk_masque_config_t,
    enabled: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        #[cfg(feature = "masque")]
        {
            let handle = require_handle_mut::<MasqueConfigHandle, lk_masque_config_t>(config)?;
            handle.config.use_native_certs = enabled;
            Ok(())
        }

        #[cfg(not(feature = "masque"))]
        {
            let _ = (config, enabled);
            Err(masque_unavailable())
        }
    })
}

/// Override the SNI and the certificate name checked on the hop to the MASQUE
/// proxy.
///
/// By default the name comes from the proxy URL's host. Override it when the
/// proxy is addressed by something its certificate does not name — most often
/// an IP address. Passing `NULL` (or a zero length) restores the default.
///
/// This changes the name the certificate must *cover*; it does not weaken the
/// check.
#[no_mangle]
pub extern "C" fn lk_masque_config_set_server_name(
    config: *mut lk_masque_config_t,
    name_ptr: *const c_char,
    name_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        #[cfg(feature = "masque")]
        {
            let handle = require_handle_mut::<MasqueConfigHandle, lk_masque_config_t>(config)?;
            if name_ptr.is_null() || name_len == 0 {
                handle.config.server_name = None;
                return Ok(());
            }
            let name = read_string_parts(name_ptr, name_len, "MASQUE server name")?;
            if name.trim().is_empty() {
                return Err(FfiError::invalid_config(
                    "MASQUE server name must not be blank; pass NULL to use the proxy host",
                ));
            }
            handle.config.server_name = Some(name);
            Ok(())
        }

        #[cfg(not(feature = "masque"))]
        {
            let _ = (config, name_ptr, name_len);
            Err(masque_unavailable())
        }
    })
}

/// Retire a MASQUE tunnel that has carried nothing for `timeout_ms`.
/// **Default: 120000.**
///
/// `0` disables idle reclamation entirely: a tunnel then lives exactly as long
/// as the inner QUIC connection using it, and the outer connection carrying it
/// is pinned for as long as any tunnel survives. That is the setting for a
/// proxy that charges per tunnel setup rather than per live tunnel —
/// `lk_masque_config_set_max_idle_tunnels` is then the only thing bounding
/// growth.
#[no_mangle]
pub extern "C" fn lk_masque_config_set_tunnel_idle_timeout(
    config: *mut lk_masque_config_t,
    timeout_ms: u64,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        #[cfg(feature = "masque")]
        {
            let handle = require_handle_mut::<MasqueConfigHandle, lk_masque_config_t>(config)?;
            handle.config.tunnel_idle_timeout = if timeout_ms == 0 {
                None
            } else {
                Some(std::time::Duration::from_millis(timeout_ms))
            };
            Ok(())
        }

        #[cfg(not(feature = "masque"))]
        {
            let _ = (config, timeout_ms);
            Err(masque_unavailable())
        }
    })
}

/// Cap the tunnels one outer MASQUE connection carries, shedding the least
/// recently active first. **Default: 256**; `0` removes the cap.
///
/// The backstop for a zero `tunnel_idle_timeout`, where nothing else bounds
/// growth: the proxy holds a UDP socket per tunnel, so a session visiting
/// thousands of origins would otherwise pin thousands of them.
#[no_mangle]
pub extern "C" fn lk_masque_config_set_max_idle_tunnels(
    config: *mut lk_masque_config_t,
    max: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        #[cfg(feature = "masque")]
        {
            let handle = require_handle_mut::<MasqueConfigHandle, lk_masque_config_t>(config)?;
            handle.config.max_idle_tunnels = max;
            Ok(())
        }

        #[cfg(not(feature = "masque"))]
        {
            let _ = (config, max);
            Err(masque_unavailable())
        }
    })
}

/// Verify the MASQUE proxy's TLS certificate. **Default: enabled.**
///
/// Pass `false` to skip certificate verification **on the hop to the proxy**.
/// **For development/testing only -- insecure!** That hop is then completely
/// open to a man in the middle: whatever answers on the proxy's address
/// terminates the outer TLS connection and sees every CONNECT-UDP target the
/// session asks for, plus the traffic pattern of everything it does. The inner
/// QUIC connection's own encryption still holds, so contents do not leak; what
/// leaks is exactly the set of origins the tunnel existed to keep private.
///
/// Reach for `lk_masque_config_add_ca_certs_pem` first — it fixes the usual
/// cause (a proxy behind a private CA) without giving up authentication. This
/// is the escape hatch for a certificate that cannot be made to verify at all,
/// such as one naming a host that does not resolve.
///
/// Distinct from `lk_client_builder_set_verify`, which governs the connection
/// to the origin. Neither implies the other, so disabling verification while
/// debugging one hop never silently disarms the other.
#[no_mangle]
pub extern "C" fn lk_masque_config_set_verify(
    config: *mut lk_masque_config_t,
    enabled: bool,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        #[cfg(feature = "masque")]
        {
            let handle = require_handle_mut::<MasqueConfigHandle, lk_masque_config_t>(config)?;
            handle.config.verify = enabled;
            Ok(())
        }

        #[cfg(not(feature = "masque"))]
        {
            let _ = (config, enabled);
            Err(masque_unavailable())
        }
    })
}

/// Free MASQUE outer-connection settings. `NULL` is a no-op.
///
/// Consumers copy the settings, so freeing this after handing it to a client or
/// pool builder is correct — and required.
#[no_mangle]
pub extern "C" fn lk_masque_config_free(config: *mut lk_masque_config_t) {
    catch_value((), || unsafe {
        #[cfg(feature = "masque")]
        handle_drop::<MasqueConfigHandle, lk_masque_config_t>(config);

        #[cfg(not(feature = "masque"))]
        {
            // No handle of this type can exist, so there is nothing to drop
            // and a non-null pointer is not ours to touch.
            let _ = config;
        }
    })
}
