use std::ptr;

use lkrequest::{AttemptLimitScope, AttemptLimits, EffectiveAttemptLimits};

use crate::abi::lk_status_t;
use crate::error::FfiError;
use crate::handles::*;
use crate::panic::catch_status;
use crate::session::SessionBuilderHandle;

/// Scope supplying the effective finite limit.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum lk_attempt_limit_scope_t {
    LK_ATTEMPT_LIMIT_UNSET = 0,
    LK_ATTEMPT_LIMIT_CLIENT = 1,
    LK_ATTEMPT_LIMIT_SESSION = 2,
    LK_ATTEMPT_LIMIT_REQUEST = 3,
    LK_ATTEMPT_LIMIT_UNKNOWN = 4,
}

/// One requested/effective limit. Values are meaningful only when present.
/// Zero is a finite limit. Clear removes an override and inherits its parent.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct lk_attempt_limit_view_t {
    pub configured_present: bool,
    pub configured: u64,
    pub effective_present: bool,
    pub effective: u64,
    pub scope: lk_attempt_limit_scope_t,
}

fn limit_view(
    configured: AttemptLimits,
    effective: EffectiveAttemptLimits,
) -> lk_attempt_limit_view_t {
    let scope = match effective.extra_http_scope() {
        Some(AttemptLimitScope::Client) => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_CLIENT,
        Some(AttemptLimitScope::Session) => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_SESSION,
        Some(AttemptLimitScope::Request) => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_REQUEST,
        None => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_UNSET,
        Some(_) => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_UNKNOWN,
    };
    lk_attempt_limit_view_t {
        configured_present: configured.extra_http_attempts().is_some(),
        configured: configured.extra_http_attempts().unwrap_or(0),
        effective_present: effective.extra_http_attempts().is_some(),
        effective: effective.extra_http_attempts().unwrap_or(0),
        scope,
    }
}

fn connect_limit_view(
    configured: AttemptLimits,
    effective: EffectiveAttemptLimits,
) -> lk_attempt_limit_view_t {
    let scope = match effective.connect_scope() {
        Some(AttemptLimitScope::Client) => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_CLIENT,
        Some(AttemptLimitScope::Session) => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_SESSION,
        Some(AttemptLimitScope::Request) => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_REQUEST,
        None => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_UNSET,
        Some(_) => lk_attempt_limit_scope_t::LK_ATTEMPT_LIMIT_UNKNOWN,
    };
    lk_attempt_limit_view_t {
        configured_present: configured.connect_attempts().is_some(),
        configured: configured.connect_attempts().unwrap_or(0),
        effective_present: effective.connect_attempts().is_some(),
        effective: effective.connect_attempts().unwrap_or(0),
        scope,
    }
}

fn session_builder_effective(
    handle: &SessionBuilderHandle,
    limits: AttemptLimits,
) -> Result<EffectiveAttemptLimits, FfiError> {
    let parent = handle
        .state
        .client
        .client
        .effective_attempt_limits()
        .map_err(FfiError::from_lkrequest)?;
    limits
        .resolve(Some(&parent), AttemptLimitScope::Session)
        .map_err(FfiError::from_lkrequest)
}

fn request_effective(
    handle: &RequestHandle,
    limits: AttemptLimits,
) -> Result<EffectiveAttemptLimits, FfiError> {
    let session = crate::request::clone_request_session(&handle.owner)?;
    let parent = session
        .effective_attempt_limits()
        .map_err(FfiError::from_lkrequest)?;
    limits
        .resolve(Some(&parent), AttemptLimitScope::Request)
        .map_err(FfiError::from_lkrequest)
}

/// Set a finite cap, including zero. A child may not relax its parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_client_builder_set_extra_http_attempt_limit(
    handle: *mut lk_client_builder_t,
    limit: u64,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(handle)?;
        let limits = handle.state.attempt_limits.with_extra_http_attempts(limit);
        limits
            .resolve(None, AttemptLimitScope::Client)
            .map_err(FfiError::from_lkrequest)?;
        handle.state.attempt_limits = limits;
        Ok(())
    })
}

/// Clear this override. Session/request levels still inherit their parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_client_builder_clear_extra_http_attempt_limit(
    handle: *mut lk_client_builder_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(handle)?;
        let limits = handle.state.attempt_limits.without_extra_http_limit();
        limits
            .resolve(None, AttemptLimitScope::Client)
            .map_err(FfiError::from_lkrequest)?;
        handle.state.attempt_limits = limits;
        Ok(())
    })
}

/// Set a finite cap, including zero. A child may not relax its parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_session_builder_set_extra_http_attempt_limit(
    handle: *mut lk_session_builder_t,
    limit: u64,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(handle)?;
        let limits = handle.state.attempt_limits.with_extra_http_attempts(limit);
        session_builder_effective(handle, limits)?;
        handle.state.attempt_limits = limits;
        Ok(())
    })
}

/// Clear this override. Session/request levels still inherit their parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_session_builder_clear_extra_http_attempt_limit(
    handle: *mut lk_session_builder_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(handle)?;
        let limits = handle.state.attempt_limits.without_extra_http_limit();
        session_builder_effective(handle, limits)?;
        handle.state.attempt_limits = limits;
        Ok(())
    })
}

/// Set a finite cap, including zero. A child may not relax its parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_request_set_extra_http_attempt_limit(
    handle: *mut lk_request_t,
    limit: u64,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle::<RequestHandle, lk_request_t>(handle)?;
        let mut state = handle.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        let limits = state.config.attempt_limits.with_extra_http_attempts(limit);
        request_effective(handle, limits)?;
        state.config.attempt_limits = limits;
        Ok(())
    })
}

/// Clear this override. Session/request levels still inherit their parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_request_clear_extra_http_attempt_limit(
    handle: *mut lk_request_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle::<RequestHandle, lk_request_t>(handle)?;
        let mut state = handle.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        let limits = state.config.attempt_limits.without_extra_http_limit();
        request_effective(handle, limits)?;
        state.config.attempt_limits = limits;
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_client_builder_get_extra_http_attempt_limit(
    handle: *const lk_client_builder_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle = require_handle::<ClientBuilderHandle, lk_client_builder_t>(handle.cast_mut())?;
        let configured = handle.state.attempt_limits;
        let effective = configured
            .resolve(None, AttemptLimitScope::Client)
            .map_err(FfiError::from_lkrequest)?;
        *out_limit = limit_view(configured, effective);
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_session_builder_get_extra_http_attempt_limit(
    handle: *const lk_session_builder_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle =
            require_handle::<SessionBuilderHandle, lk_session_builder_t>(handle.cast_mut())?;
        let configured = handle.state.attempt_limits;
        let effective = session_builder_effective(handle, configured)?;
        *out_limit = limit_view(configured, effective);
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_request_get_extra_http_attempt_limit(
    handle: *const lk_request_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle = require_handle::<RequestHandle, lk_request_t>(handle.cast_mut())?;
        let configured = handle.state.lock().config.attempt_limits;
        let effective = request_effective(handle, configured)?;
        *out_limit = limit_view(configured, effective);
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_client_get_extra_http_attempt_limit(
    handle: *const lk_client_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle = require_handle::<ClientHandle, lk_client_t>(handle.cast_mut())?;
        let configured = handle.shared.client.configured_attempt_limits();
        let effective = handle
            .shared
            .client
            .effective_attempt_limits()
            .map_err(FfiError::from_lkrequest)?;
        *out_limit = limit_view(configured, effective);
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_session_get_extra_http_attempt_limit(
    handle: *const lk_session_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle = require_handle::<SessionHandle, lk_session_t>(handle.cast_mut())?;
        let configured = handle.shared.session.configured_attempt_limits();
        let effective = handle
            .shared
            .session
            .effective_attempt_limits()
            .map_err(FfiError::from_lkrequest)?;
        *out_limit = limit_view(configured, effective);
        Ok(())
    })
}

/// Set a finite cap, including zero. A child may not relax its parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_client_builder_set_connect_attempt_limit(
    handle: *mut lk_client_builder_t,
    limit: u64,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(handle)?;
        let limits = handle.state.attempt_limits.with_connect_attempts(limit);
        limits
            .resolve(None, AttemptLimitScope::Client)
            .map_err(FfiError::from_lkrequest)?;
        handle.state.attempt_limits = limits;
        Ok(())
    })
}

/// Clear this override. Session/request levels still inherit their parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_client_builder_clear_connect_attempt_limit(
    handle: *mut lk_client_builder_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle_mut::<ClientBuilderHandle, lk_client_builder_t>(handle)?;
        let limits = handle.state.attempt_limits.without_connect_limit();
        limits
            .resolve(None, AttemptLimitScope::Client)
            .map_err(FfiError::from_lkrequest)?;
        handle.state.attempt_limits = limits;
        Ok(())
    })
}

/// Set a finite cap, including zero. A child may not relax its parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_session_builder_set_connect_attempt_limit(
    handle: *mut lk_session_builder_t,
    limit: u64,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(handle)?;
        let limits = handle.state.attempt_limits.with_connect_attempts(limit);
        session_builder_effective(handle, limits)?;
        handle.state.attempt_limits = limits;
        Ok(())
    })
}

/// Clear this override. Session/request levels still inherit their parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_session_builder_clear_connect_attempt_limit(
    handle: *mut lk_session_builder_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle_mut::<SessionBuilderHandle, lk_session_builder_t>(handle)?;
        let limits = handle.state.attempt_limits.without_connect_limit();
        session_builder_effective(handle, limits)?;
        handle.state.attempt_limits = limits;
        Ok(())
    })
}

/// Set a finite cap, including zero. A child may not relax its parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_request_set_connect_attempt_limit(
    handle: *mut lk_request_t,
    limit: u64,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle::<RequestHandle, lk_request_t>(handle)?;
        let mut state = handle.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        let limits = state.config.attempt_limits.with_connect_attempts(limit);
        request_effective(handle, limits)?;
        state.config.attempt_limits = limits;
        Ok(())
    })
}

/// Clear this override. Session/request levels still inherit their parent.
/// Failure leaves the previous configuration intact.
#[no_mangle]
pub extern "C" fn lk_request_clear_connect_attempt_limit(
    handle: *mut lk_request_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle::<RequestHandle, lk_request_t>(handle)?;
        let mut state = handle.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        let limits = state.config.attempt_limits.without_connect_limit();
        request_effective(handle, limits)?;
        state.config.attempt_limits = limits;
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_client_builder_get_connect_attempt_limit(
    handle: *const lk_client_builder_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle = require_handle::<ClientBuilderHandle, lk_client_builder_t>(handle.cast_mut())?;
        let configured = handle.state.attempt_limits;
        let effective = configured
            .resolve(None, AttemptLimitScope::Client)
            .map_err(FfiError::from_lkrequest)?;
        *out_limit = connect_limit_view(configured, effective);
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_session_builder_get_connect_attempt_limit(
    handle: *const lk_session_builder_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle =
            require_handle::<SessionBuilderHandle, lk_session_builder_t>(handle.cast_mut())?;
        let configured = handle.state.attempt_limits;
        let effective = session_builder_effective(handle, configured)?;
        *out_limit = connect_limit_view(configured, effective);
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_request_get_connect_attempt_limit(
    handle: *const lk_request_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle = require_handle::<RequestHandle, lk_request_t>(handle.cast_mut())?;
        let configured = handle.state.lock().config.attempt_limits;
        let effective = request_effective(handle, configured)?;
        *out_limit = connect_limit_view(configured, effective);
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_client_get_connect_attempt_limit(
    handle: *const lk_client_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle = require_handle::<ClientHandle, lk_client_t>(handle.cast_mut())?;
        let configured = handle.shared.client.configured_attempt_limits();
        let effective = handle
            .shared
            .client
            .effective_attempt_limits()
            .map_err(FfiError::from_lkrequest)?;
        *out_limit = connect_limit_view(configured, effective);
        Ok(())
    })
}

/// Read requested and effective values without changing configuration.
#[no_mangle]
pub extern "C" fn lk_session_get_connect_attempt_limit(
    handle: *const lk_session_t,
    out_limit: *mut lk_attempt_limit_view_t,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        if out_limit.is_null() {
            return Err(FfiError::invalid_argument("out_limit is null"));
        }
        let handle = require_handle::<SessionHandle, lk_session_t>(handle.cast_mut())?;
        let configured = handle.shared.session.configured_attempt_limits();
        let effective = handle
            .shared
            .session
            .effective_attempt_limits()
            .map_err(FfiError::from_lkrequest)?;
        *out_limit = connect_limit_view(configured, effective);
        Ok(())
    })
}

/// Enable separate attempt summaries before sending. Disabled by default.
/// This setting does not change diagnostics JSON or enable any retries.
#[no_mangle]
pub extern "C" fn lk_request_enable_attempt_summary(
    request: *mut lk_request_t,
    enabled: bool,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let request = require_handle::<RequestHandle, lk_request_t>(request)?;
        let mut state = request.state.lock();
        if matches!(state.lifecycle, RequestLifecycle::Consumed) {
            return Err(FfiError::invalid_argument(
                "request has already been consumed",
            ));
        }
        state.config.observe_attempts = enabled;
        Ok(())
    })
}

pub(crate) fn attach_error_observer(
    out_err: *mut *mut lk_error_t,
    observer: Option<lkrequest::AttemptObserver>,
) {
    if observer.is_none() || out_err.is_null() {
        return;
    }
    unsafe {
        if !(*out_err).is_null() {
            if let Ok(error) = require_handle_mut::<ErrorHandle, lk_error_t>(*out_err) {
                error.observer = observer;
            }
        }
    }
}

unsafe fn copy_summary(
    observer: Option<&lkrequest::AttemptObserver>,
    buffer: *mut u8,
    capacity: usize,
    out_required: *mut usize,
) -> Result<(), FfiError> {
    if out_required.is_null() {
        return Err(FfiError::invalid_argument("out_required is null"));
    }
    *out_required = 0;
    if buffer.is_null() && capacity != 0 {
        return Err(FfiError::invalid_argument(
            "buffer is null while capacity is nonzero",
        ));
    }
    let observer = observer.ok_or_else(|| {
        FfiError::invalid_argument("attempt summary was not enabled for this operation")
    })?;
    let snapshot = observer.snapshot();
    let effective = snapshot.effective_limits().map(|limits| {
        serde_json::json!({
            "extra_http_attempts": limits.extra_http_attempts(),
            "extra_http_scope": limits.extra_http_scope().map(AttemptLimitScope::as_str),
            "connect_attempts": limits.connect_attempts(),
            "connect_scope": limits.connect_scope().map(AttemptLimitScope::as_str),
        })
    });
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "started": snapshot.started(),
        "effective_limits": effective,
        "http_submissions": snapshot.http_submissions(),
        "extra_http_submissions": snapshot.extra_http_submissions(),
        "redirects": snapshot.redirects(),
        "recoveries": snapshot.recoveries(),
        "connect_initiations": snapshot.connect_initiations(),
        "probe_suppressed_by_connect_limit": snapshot.probe_suppressed_by_connect_limit(),
        "outcome": snapshot.outcome().as_str(),
        "final": snapshot.outcome().is_final(),
        "denial_reason": snapshot.denial_reason().map(|reason| reason.as_str()),
    }))
    .map_err(|error| {
        FfiError::new(
            crate::abi::lk_error_code_t::LK_ERR_UNKNOWN,
            error.to_string(),
        )
    })?;
    *out_required = bytes.len();
    if buffer.is_null() {
        return Ok(());
    }
    if capacity < bytes.len() {
        return Err(FfiError::invalid_argument(
            "attempt summary buffer is too small",
        ));
    }
    ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
    Ok(())
}

/// Copy a fresh JSON snapshot without a trailing NUL. NULL/0 queries required size.
/// Insufficient capacity writes only out_required and returns LK_ERR. Retry with
/// a larger buffer if an active snapshot grows. Counts settle when final is true.
/// An operation retains its summary after cancellation and result consumption.
#[no_mangle]
pub extern "C" fn lk_response_copy_attempt_summary_json(
    handle: *const lk_response_t,
    buffer: *mut u8,
    capacity: usize,
    out_required: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle::<ResponseHandle, lk_response_t>(handle.cast_mut())?;
        copy_summary(handle.observer.as_ref(), buffer, capacity, out_required)
    })
}

/// Copy a fresh JSON snapshot without a trailing NUL. NULL/0 queries required size.
/// Insufficient capacity writes only out_required and returns LK_ERR. Retry with
/// a larger buffer if an active snapshot grows. Counts settle when final is true.
/// An operation retains its summary after cancellation and result consumption.
#[no_mangle]
pub extern "C" fn lk_streaming_response_copy_attempt_summary_json(
    handle: *const lk_streaming_response_t,
    buffer: *mut u8,
    capacity: usize,
    out_required: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle =
            require_handle::<StreamingResponseHandle, lk_streaming_response_t>(handle.cast_mut())?;
        copy_summary(handle.observer.as_ref(), buffer, capacity, out_required)
    })
}

/// Copy a fresh JSON snapshot without a trailing NUL. NULL/0 queries required size.
/// Insufficient capacity writes only out_required and returns LK_ERR. Retry with
/// a larger buffer if an active snapshot grows. Counts settle when final is true.
/// An operation retains its summary after cancellation and result consumption.
#[no_mangle]
pub extern "C" fn lk_error_copy_attempt_summary_json(
    handle: *const lk_error_t,
    buffer: *mut u8,
    capacity: usize,
    out_required: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle::<ErrorHandle, lk_error_t>(handle.cast_mut())?;
        copy_summary(handle.observer.as_ref(), buffer, capacity, out_required)
    })
}

/// Copy a fresh JSON snapshot without a trailing NUL. NULL/0 queries required size.
/// Insufficient capacity writes only out_required and returns LK_ERR. Retry with
/// a larger buffer if an active snapshot grows. Counts settle when final is true.
/// An operation retains its summary after cancellation and result consumption.
#[no_mangle]
pub extern "C" fn lk_op_copy_attempt_summary_json(
    handle: *const lk_op_t,
    buffer: *mut u8,
    capacity: usize,
    out_required: *mut usize,
    out_err: *mut *mut lk_error_t,
) -> lk_status_t {
    catch_status(out_err, || unsafe {
        let handle = require_handle::<OpHandle, lk_op_t>(handle.cast_mut())?;
        copy_summary(handle.observer.as_ref(), buffer, capacity, out_required)
    })
}
