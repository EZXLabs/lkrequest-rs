#include "../include/lkrequest.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LK_EXPECT_POINTER_BITS
_Static_assert(sizeof(void*) * 8 == LK_EXPECT_POINTER_BITS, "unexpected pointer width");
#endif
_Static_assert(sizeof(size_t) == sizeof(void*), "size_t must match pointer width");
_Static_assert(sizeof(lk_status_t) == 4, "status must use the 32-bit C ABI");
_Static_assert(sizeof(lk_attempt_limit_scope_t) == 4, "attempt limit scope must use the 32-bit C ABI");
_Static_assert(sizeof(lk_bytes_view_t) == 2 * sizeof(void*), "unexpected byte view layout");

int main(void) {
    if (lk_abi_version() != 1) {
        fprintf(stderr, "unexpected abi version\n");
        return 1;
    }

    lk_client_t* client = NULL;
    lk_session_t* session = NULL;
    lk_request_t* request = NULL;
    lk_error_t* error = NULL;

    if (!lk_feature_supported("tls-profile-json") ||
        !lk_feature_supported("h2-profile-json") ||
        !lk_feature_supported("extra-http-attempt-limit") ||
        !lk_feature_supported("connect-attempt-limit") ||
        !lk_feature_supported("attempt-summary")) {
        fprintf(stderr, "editable TLS profile capabilities missing\n");
        return 1;
    }
    lk_client_builder_t* profile_builder = lk_client_builder_new();
    size_t bundle_len = 0;
    if (!lk_feature_supported("preset-bundle-v2") ||
        lk_preset_export_json("chrome_158", 10, NULL, 0, &bundle_len, &error) != LK_OK) {
        fprintf(stderr, "preset bundle export query failed\n");
        return 1;
    }
    char* bundle = malloc(bundle_len + 1);
    if (bundle == NULL ||
        lk_preset_export_json("chrome_158", 10, bundle, bundle_len + 1, &bundle_len, &error) != LK_OK ||
        bundle[bundle_len] != '\0' ||
        lk_client_builder_set_preset_json(profile_builder, bundle, bundle_len, &error) != LK_OK) {
        fprintf(stderr, "preset bundle ABI failed\n");
        free(bundle);
        return 1;
    }
    free(bundle);
    if (lk_client_builder_set_preset_file(profile_builder, "missing-preset.json", 19, &error) != LK_ERR ||
        lk_error_code(error) != LK_ERR_IO) {
        fprintf(stderr, "preset file ABI failed\n");
        return 1;
    }
    lk_error_free(error);
    error = NULL;
    if (lk_client_builder_set_preset_json(profile_builder, NULL, 0, &error) != LK_OK) {
        return 1;
    }
    const char* profile_json =
        "{\"name\":\"c-custom\",\"tls_min_version\":\"tls12\","
        "\"tls_max_version\":\"tls13\",\"cipher_suites\":[4865],"
        "\"extensions\":[],\"supported_groups\":[29],"
        "\"signature_algorithms\":[1027],\"key_share_curves\":[29]}";
    if (lk_client_builder_set_tls_profile_json(profile_builder, profile_json,
                                               strlen(profile_json)) != LK_OK ||
        lk_client_builder_set_tls_profile_json(profile_builder, NULL, 0) != LK_OK) {
        fprintf(stderr, "editable TLS profile setter ABI failed\n");
        lk_client_builder_free(profile_builder);
        return 1;
    }
    const char* h2_json =
        "{\"settings\":[{\"id\":\"initial_window_size\",\"value\":65535}],"
        "\"window_update\":12345,"
        "\"pseudo_header_order\":[\"method\",\"authority\",\"scheme\",\"path\"]}";
    if (lk_client_builder_set_h2_profile_json(profile_builder, h2_json,
                                              strlen(h2_json)) != LK_OK ||
        lk_client_builder_set_h2_profile_json(profile_builder, "{}", 2) != LK_ERR ||
        lk_client_builder_set_h2_profile_json(profile_builder, NULL, 0) != LK_OK) {
        fprintf(stderr, "custom H2 profile setter ABI failed\n");
        lk_client_builder_free(profile_builder);
        return 1;
    }
    lk_status_t quic_expected = lk_feature_supported("quic-tls-profile-json") ? LK_OK : LK_ERR;
    if (lk_client_builder_set_quic_tls_profile_json(profile_builder, profile_json,
                                                    strlen(profile_json)) != quic_expected ||
        lk_client_builder_clear_quic_fingerprint(profile_builder) != quic_expected ||
        lk_client_builder_set_quic_tls_profile_json(profile_builder, NULL, 0) != quic_expected) {
        fprintf(stderr, "custom QUIC TLS setter ABI failed\n");
        lk_client_builder_free(profile_builder);
        return 1;
    }
    lk_attempt_limit_view_t limit = {0};
    if (lk_client_builder_set_extra_http_attempt_limit(profile_builder, UINT64_MAX, &error) != LK_OK ||
        lk_client_builder_get_extra_http_attempt_limit(profile_builder, &limit, &error) != LK_OK ||
        !limit.configured_present || limit.configured != UINT64_MAX ||
        !limit.effective_present || limit.effective != UINT64_MAX ||
        limit.scope != LK_ATTEMPT_LIMIT_CLIENT ||
        lk_client_builder_set_extra_http_attempt_limit(profile_builder, 0, &error) != LK_OK ||
        lk_client_builder_get_extra_http_attempt_limit(profile_builder, &limit, &error) != LK_OK ||
        !limit.effective_present || limit.effective != 0 ||
        lk_client_builder_clear_extra_http_attempt_limit(profile_builder, &error) != LK_OK ||
        lk_client_builder_get_extra_http_attempt_limit(profile_builder, &limit, &error) != LK_OK ||
        limit.configured_present || limit.effective_present || limit.scope != LK_ATTEMPT_LIMIT_UNSET) {
        fprintf(stderr, "client attempt limit ABI failed\n");
        return 1;
    }
    if (lk_client_builder_set_connect_attempt_limit(profile_builder, UINT64_MAX, &error) != LK_OK ||
        lk_client_builder_get_connect_attempt_limit(profile_builder, &limit, &error) != LK_OK ||
        !limit.configured_present || limit.configured != UINT64_MAX ||
        !limit.effective_present || limit.effective != UINT64_MAX ||
        limit.scope != LK_ATTEMPT_LIMIT_CLIENT ||
        lk_client_builder_set_connect_attempt_limit(profile_builder, 0, &error) != LK_OK ||
        lk_client_builder_get_connect_attempt_limit(profile_builder, &limit, &error) != LK_OK ||
        !limit.effective_present || limit.effective != 0 ||
        lk_client_builder_clear_connect_attempt_limit(profile_builder, &error) != LK_OK ||
        lk_client_builder_get_connect_attempt_limit(profile_builder, &limit, &error) != LK_OK ||
        limit.configured_present || limit.effective_present) {
        fprintf(stderr, "client connect limit ABI failed\n");
        return 1;
    }
    lk_client_builder_free(profile_builder);

    if (lk_client_new_default(&client, &error) != LK_OK) {
        fprintf(stderr, "lk_client_new_default failed\n");
        return 1;
    }

    if (lk_session_new(client, &session, &error) != LK_OK) {
        fprintf(stderr, "lk_session_new failed\n");
        lk_client_free(client);
        return 1;
    }

    lk_session_builder_t* limit_builder = lk_session_builder_new(client);
    if (limit_builder == NULL ||
        lk_client_get_extra_http_attempt_limit(client, &limit, &error) != LK_OK ||
        limit.effective_present ||
        lk_session_builder_set_extra_http_attempt_limit(limit_builder, 0, &error) != LK_OK ||
        lk_session_builder_get_extra_http_attempt_limit(limit_builder, &limit, &error) != LK_OK ||
        !limit.configured_present || !limit.effective_present || limit.effective != 0 ||
        limit.scope != LK_ATTEMPT_LIMIT_SESSION ||
        lk_session_builder_clear_extra_http_attempt_limit(limit_builder, &error) != LK_OK ||
        lk_session_builder_get_extra_http_attempt_limit(limit_builder, &limit, &error) != LK_OK ||
        limit.configured_present || limit.effective_present ||
        lk_session_get_extra_http_attempt_limit(session, &limit, &error) != LK_OK ||
        limit.effective_present) {
        fprintf(stderr, "session attempt limit ABI failed\n");
        return 1;
    }
    if (lk_client_get_connect_attempt_limit(client, &limit, &error) != LK_OK ||
        limit.effective_present ||
        lk_session_builder_set_connect_attempt_limit(limit_builder, 0, &error) != LK_OK ||
        lk_session_builder_get_connect_attempt_limit(limit_builder, &limit, &error) != LK_OK ||
        !limit.configured_present || !limit.effective_present || limit.effective != 0 ||
        limit.scope != LK_ATTEMPT_LIMIT_SESSION ||
        lk_session_builder_clear_connect_attempt_limit(limit_builder, &error) != LK_OK ||
        lk_session_builder_get_connect_attempt_limit(limit_builder, &limit, &error) != LK_OK ||
        limit.configured_present || limit.effective_present ||
        lk_session_get_connect_attempt_limit(session, &limit, &error) != LK_OK ||
        limit.effective_present) {
        fprintf(stderr, "session connect limit ABI failed\n");
        return 1;
    }
    lk_session_builder_free(limit_builder);

    const char* cookies = NULL;
    size_t cookies_len = 0;
    if (lk_session_get_all_cookies_json(session, &cookies, &cookies_len, &error) != LK_OK ||
        cookies == NULL || cookies_len != 2 || strcmp(cookies, "[]") != 0) {
        fprintf(stderr, "all-cookie JSON ABI failed\n");
        return 1;
    }
    const char* cookie_url = "https://example.test/";
    if (lk_session_get_cookies_with_attrs_json(
            session, cookie_url, strlen(cookie_url), &cookies, &cookies_len, &error) != LK_OK ||
        cookies == NULL || cookies_len != 2 || strcmp(cookies, "[]") != 0) {
        fprintf(stderr, "cookie-attribute JSON ABI failed\n");
        return 1;
    }

    const char* method = "GET";
    const char* url = "://bad";
    if (lk_request_new(
            session,
            method,
            strlen(method),
            url,
            strlen(url),
            &request,
            &error) != LK_OK) {
        fprintf(stderr, "lk_request_new failed\n");
        lk_session_free(session);
        lk_client_free(client);
        return 1;
    }

    if (lk_request_set_extra_http_attempt_limit(request, UINT64_MAX, &error) != LK_OK ||
        lk_request_get_extra_http_attempt_limit(request, &limit, &error) != LK_OK ||
        !limit.effective_present || limit.effective != UINT64_MAX ||
        limit.scope != LK_ATTEMPT_LIMIT_REQUEST ||
        lk_request_clear_extra_http_attempt_limit(request, &error) != LK_OK ||
        lk_request_get_extra_http_attempt_limit(request, &limit, &error) != LK_OK ||
        limit.configured_present || limit.effective_present ||
        lk_request_set_extra_http_attempt_limit(request, 0, &error) != LK_OK ||
        lk_request_get_extra_http_attempt_limit(request, &limit, &error) != LK_OK ||
        !limit.effective_present || limit.effective != 0 ||
        lk_request_enable_attempt_summary(request, true, &error) != LK_OK) {
        fprintf(stderr, "request attempt limit ABI failed\n");
        return 1;
    }
    if (lk_request_set_connect_attempt_limit(request, UINT64_MAX, &error) != LK_OK ||
        lk_request_get_connect_attempt_limit(request, &limit, &error) != LK_OK ||
        !limit.effective_present || limit.effective != UINT64_MAX ||
        limit.scope != LK_ATTEMPT_LIMIT_REQUEST ||
        lk_request_clear_connect_attempt_limit(request, &error) != LK_OK ||
        lk_request_get_connect_attempt_limit(request, &limit, &error) != LK_OK ||
        limit.configured_present || limit.effective_present ||
        lk_request_set_connect_attempt_limit(request, 0, &error) != LK_OK ||
        lk_request_get_connect_attempt_limit(request, &limit, &error) != LK_OK ||
        !limit.effective_present || limit.effective != 0) {
        fprintf(stderr, "request connect limit ABI failed\n");
        return 1;
    }

    lk_response_t* response = NULL;
    if (lk_request_send(request, &response, &error) != LK_ERR) {
        fprintf(stderr, "expected request failure for invalid URL\n");
        if (response != NULL) {
            lk_response_free(response);
        }
        lk_request_free(request);
        lk_session_free(session);
        lk_client_free(client);
        return 1;
    }

    const char* msg_ptr = NULL;
    size_t msg_len = 0;
    if (error == NULL || lk_error_message(error, &msg_ptr, &msg_len) != LK_OK) {
        fprintf(stderr, "missing error message\n");
        lk_request_free(request);
        lk_session_free(session);
        lk_client_free(client);
        return 1;
    }

    lk_error_t* copy_error = NULL;
    size_t summary_len = 0;
    if (lk_error_copy_attempt_summary_json(error, NULL, 0, &summary_len, &copy_error) != LK_OK ||
        summary_len == 0 || copy_error != NULL) {
        fprintf(stderr, "attempt summary size query failed\n");
        return 1;
    }
    uint8_t small[4] = {0x5a, 0x5a, 0x5a, 0x5a};
    size_t required = 0;
    if (lk_error_copy_attempt_summary_json(error, small, sizeof(small), &required, &copy_error) != LK_ERR ||
        copy_error == NULL || required != summary_len ||
        small[0] != 0x5a || small[1] != 0x5a || small[2] != 0x5a || small[3] != 0x5a) {
        fprintf(stderr, "attempt summary buffer contract failed\n");
        return 1;
    }
    lk_error_free(copy_error);
    copy_error = NULL;
    uint8_t* summary = malloc(summary_len + 1);
    if (summary == NULL ||
        lk_error_copy_attempt_summary_json(error, summary, summary_len, &required, &copy_error) != LK_OK ||
        required != summary_len || copy_error != NULL) {
        fprintf(stderr, "attempt summary copy failed\n");
        free(summary);
        return 1;
    }
    summary[summary_len] = '\0';
    if (strstr((const char*)summary, "\"outcome\":\"failed\"") == NULL ||
        strstr((const char*)summary, "\"http_submissions\":0") == NULL ||
        strstr((const char*)summary, "\"extra_http_attempts\":0") == NULL ||
        strstr((const char*)summary, "\"connect_attempts\":0") == NULL ||
        strstr((const char*)summary, "\"connect_initiations\":0") == NULL ||
        strstr((const char*)summary, "\"probe_suppressed_by_connect_limit\":false") == NULL ||
        lk_error_code(error) != LK_ERR_URL_PARSE) {
        fprintf(stderr, "attempt summary changed the original error or counts\n");
        free(summary);
        return 1;
    }
    free(summary);

    printf("abi=%u\n", (unsigned)lk_abi_version());
    printf("pointer_bits=%u\n", (unsigned)(sizeof(void*) * 8));
    printf("library=%s\n", lk_library_version());
    printf("expected error: %.*s\n", (int)msg_len, msg_ptr);

    if (error != NULL) {
        lk_error_free(error);
    }
    lk_request_free(request);
    lk_session_free(session);
    lk_client_free(client);
    return 0;
}
