//! Proxy configuration handles.
//!
//! A proxy URL can only express username/password credentials. MASQUE and HTTP
//! CONNECT deployments also use static header credentials (`Preshared`,
//! `PrivateToken`, `Bearer`, …) and disagree on whether those travel in
//! `Proxy-Authorization` or `Authorization`, so those configurations are built
//! on an `lk_proxy_config_t` handle and handed to a Session or ProxyPool.
//!
//! `ProxyCredential::Custom` has no equivalent here: it is a Rust trait object
//! and cannot cross the C ABI.

use std::ffi::c_char;
use std::ptr;

use crate::abi::{lk_proxy_auth_header_t, lk_status_t};
use crate::conv::{clear_out_len, clear_out_ptr, read_string_parts, set_string_out};
use crate::error::FfiError;
use crate::handles::{
    box_into_handle, handle_drop, lk_proxy_config_t, require_handle, require_handle_mut,
    ProxyConfigHandle,
};
use crate::panic::{catch_status, catch_value, null_error_out};

fn map_auth_header(header: lk_proxy_auth_header_t) -> lkrequest::proxy::ProxyAuthHeader {
    match header {
        lk_proxy_auth_header_t::LK_PROXY_AUTH_HEADER_PROXY_AUTHORIZATION => {
            lkrequest::proxy::ProxyAuthHeader::ProxyAuthorization
        }
        lk_proxy_auth_header_t::LK_PROXY_AUTH_HEADER_AUTHORIZATION => {
            lkrequest::proxy::ProxyAuthHeader::Authorization
        }
    }
}

/// Parse a proxy URL into a configuration handle.
///
/// Accepts `http`, `https`, `socks5` and `socks5h`, plus `masque` (RFC 9298
/// CONNECT-UDP; the port defaults to 443) when this library was built with the
/// `masque` feature. Without it a `masque://` URL fails with
/// `LK_ERR_INVALID_CONFIG` and an error message naming the feature to rebuild
/// with, rather than yielding a configuration no request could ever use.
/// Returns `LK_OK` and writes the handle to `out_config`; free it with
/// `lk_proxy_config_free`.
#[no_mangle]
pub extern "C" fn lk_proxy_config_parse(
    url_ptr: *const c_char,
    url_len: usize,
    out_config: *mut *mut lk_proxy_config_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        if out_config.is_null() {
            return Err(FfiError::invalid_argument("out_config is null"));
        }
        *out_config = ptr::null_mut();
        let url = read_string_parts(url_ptr, url_len, "proxy URL")?;
        let config = lkrequest::proxy::ProxyConfig::parse(&url)
            .map_err(|err| FfiError::invalid_config(format!("invalid proxy URL: {err}")))?;
        *out_config =
            box_into_handle::<ProxyConfigHandle, lk_proxy_config_t>(ProxyConfigHandle::new(config));
        Ok(())
    })
}

/// Replace this proxy's credentials with a username/password pair.
#[no_mangle]
pub extern "C" fn lk_proxy_config_set_user_pass(
    config: *mut lk_proxy_config_t,
    username_ptr: *const c_char,
    username_len: usize,
    password_ptr: *const c_char,
    password_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let handle = require_handle_mut::<ProxyConfigHandle, lk_proxy_config_t>(config)?;
        let username = read_string_parts(username_ptr, username_len, "proxy username")?;
        let password = read_string_parts(password_ptr, password_len, "proxy password")?;
        let updated = handle
            .config
            .clone()
            .with_user_pass(username, password)
            .map_err(|err| FfiError::invalid_config(err.to_string()))?;
        handle.config = updated;
        handle.refresh();
        Ok(())
    })
}

/// Authenticate with a static HTTP auth-scheme and already-encoded credentials,
/// e.g. `("Preshared", "<psk>")` or `("PrivateToken", "token=<b64>")`.
///
/// Fails with `LK_ERR_INVALID_CONFIG` when this proxy is SOCKS5: the SOCKS5
/// handshake has no request headers to carry the credential.
#[no_mangle]
pub extern "C" fn lk_proxy_config_set_http_auth(
    config: *mut lk_proxy_config_t,
    scheme_ptr: *const c_char,
    scheme_len: usize,
    credentials_ptr: *const c_char,
    credentials_len: usize,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let handle = require_handle_mut::<ProxyConfigHandle, lk_proxy_config_t>(config)?;
        let scheme = read_string_parts(scheme_ptr, scheme_len, "proxy auth scheme")?;
        let credentials =
            read_string_parts(credentials_ptr, credentials_len, "proxy auth credentials")?;
        if scheme.trim().is_empty() {
            return Err(FfiError::invalid_config(
                "proxy auth scheme must not be empty",
            ));
        }
        let updated = handle
            .config
            .clone()
            .with_http_auth(scheme, credentials)
            .map_err(|err| FfiError::invalid_config(err.to_string()))?;
        handle.config = updated;
        handle.refresh();
        Ok(())
    })
}

/// Select which header carries HTTP-based credentials
/// (`Proxy-Authorization` by default).
#[no_mangle]
pub extern "C" fn lk_proxy_config_set_auth_header(
    config: *mut lk_proxy_config_t,
    header: lk_proxy_auth_header_t,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        let handle = require_handle_mut::<ProxyConfigHandle, lk_proxy_config_t>(config)?;
        handle.config.auth_header = map_auth_header(header);
        handle.refresh();
        Ok(())
    })
}

/// Borrow this proxy's URL rendering (`scheme://[user:pass@]host:port`).
///
/// The pointer stays valid until the handle is mutated or freed. Credentials
/// set with `lk_proxy_config_set_http_auth` have no URL form and do not appear.
#[no_mangle]
pub extern "C" fn lk_proxy_config_url(
    config: *const lk_proxy_config_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let handle = require_handle::<ProxyConfigHandle, lk_proxy_config_t>(config.cast_mut())?;
        set_string_out(&handle.url, out_ptr, out_len)
    })
}

/// Borrow this proxy's identity — the key used for cooldown and blacklisting.
///
/// Opaque; never contains passwords or encoded credentials.
#[no_mangle]
pub extern "C" fn lk_proxy_config_identity(
    config: *const lk_proxy_config_t,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        clear_out_ptr(out_ptr);
        clear_out_len(out_len);
        let handle = require_handle::<ProxyConfigHandle, lk_proxy_config_t>(config.cast_mut())?;
        set_string_out(&handle.identity, out_ptr, out_len)
    })
}

/// Free a proxy configuration handle.
#[no_mangle]
pub extern "C" fn lk_proxy_config_free(config: *mut lk_proxy_config_t) {
    catch_value((), || unsafe {
        handle_drop::<ProxyConfigHandle, lk_proxy_config_t>(config);
    })
}

/// Borrow the inner `ProxyConfig` from a handle.
pub(crate) unsafe fn proxy_config_ref(
    config: *const lk_proxy_config_t,
) -> Result<&'static lkrequest::proxy::ProxyConfig, FfiError> {
    let handle = require_handle::<ProxyConfigHandle, lk_proxy_config_t>(config.cast_mut())?;
    Ok(&handle.config)
}
