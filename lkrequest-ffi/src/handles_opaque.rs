#[repr(C)]
pub struct lk_client_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_client_builder_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_session_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_session_builder_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_request_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_response_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_streaming_response_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_error_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_op_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_proxy_config_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_proxy_pool_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_proxy_pool_builder_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_proxy_guard_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_socks5_udp_probe_report_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_session_pool_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_session_pool_builder_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_session_pool_guard_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct lk_multipart_t {
    _private: [u8; 0],
}

/// MASQUE outer-connection settings (`lk_masque_config_*`).
///
/// The type exists in every build so the generated header does not change
/// shape with the `masque` feature; without that feature
/// `lk_masque_config_new` refuses to produce one.
#[repr(C)]
pub struct lk_masque_config_t {
    _private: [u8; 0],
}
