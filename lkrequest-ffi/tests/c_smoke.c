#include "../include/lkrequest.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef LK_EXPECT_POINTER_BITS
_Static_assert(sizeof(void*) * 8 == LK_EXPECT_POINTER_BITS, "unexpected pointer width");
#endif
_Static_assert(sizeof(size_t) == sizeof(void*), "size_t must match pointer width");
_Static_assert(sizeof(lk_status_t) == 4, "status must use the 32-bit C ABI");
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

    if (lk_client_new_default(&client, &error) != LK_OK) {
        fprintf(stderr, "lk_client_new_default failed\n");
        return 1;
    }

    if (lk_session_new(client, &session, &error) != LK_OK) {
        fprintf(stderr, "lk_session_new failed\n");
        lk_client_free(client);
        return 1;
    }

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
