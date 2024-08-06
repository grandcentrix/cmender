/*
 * Copyright (C) 2019 grandcentrix GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MENDER_HTTP_H
#define MENDER_HTTP_H

#include <mender/error.h>
#include <mender/transport.h>
#include <mender/platform/config.h>
#include <http_parser.h>
#include <mender/stack.h>

enum mender_http_state {
    MENDER_HTTP_STATE_INITIALIZED = 0,
    MENDER_HTTP_STATE_CONNECT,
    MENDER_HTTP_STATE_CONNECTED,

    MENDER_HTTP_STATE_SEND_METHOD,
    MENDER_HTTP_STATE_SEND_PATH,
    MENDER_HTTP_STATE_SEND_QUERY_SEP,
    MENDER_HTTP_STATE_SEND_QUERY,
    MENDER_HTTP_STATE_SEND_HTTPVER,

    MENDER_HTTP_STATE_SEND_HOST_KEY,
    MENDER_HTTP_STATE_SEND_HOST_NAME,
    MENDER_HTTP_STATE_SEND_HOST_COLON,
    MENDER_HTTP_STATE_SEND_HOST_PORT,
    MENDER_HTTP_STATE_SEND_HOST_END,

    MENDER_HTTP_STATE_SEND_USER_HDR,

    MENDER_HTTP_STATE_READ_HDR_FIELD,
    MENDER_HTTP_STATE_READ_HDR_VALUE,
    MENDER_HTTP_STATE_CLOSE_REQUESTED,
    MENDER_HTTP_STATE_CLOSED
};

enum mender_http_close_reason {
    MENDER_HTTP_CR_CLOSED = 0,
    MENDER_HTTP_CR_PARSING_ERROR,
    MENDER_HTTP_CR_INTERNAL_ERROR
};

enum mender_http_method {
    MENDER_HTTP_METHOD_GET,
    MENDER_HTTP_METHOD_POST,
    MENDER_HTTP_METHOD_PUT,
    MENDER_HTTP_METHOD_PATCH
};

enum mender_http_status {
  HTTP_STATUS_CONTINUE = 100,
  HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
  HTTP_STATUS_PROCESSING = 102,
  HTTP_STATUS_EARLY_HINTS = 103,
  HTTP_STATUS_RESPONSE_IS_STALE = 110,
  HTTP_STATUS_REVALIDATION_FAILED = 111,
  HTTP_STATUS_DISCONNECTED_OPERATION = 112,
  HTTP_STATUS_HEURISTIC_EXPIRATION = 113,
  HTTP_STATUS_MISCELLANEOUS_WARNING = 199,
  HTTP_STATUS_OK = 200,
  HTTP_STATUS_CREATED = 201,
  HTTP_STATUS_ACCEPTED = 202,
  HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
  HTTP_STATUS_NO_CONTENT = 204,
  HTTP_STATUS_RESET_CONTENT = 205,
  HTTP_STATUS_PARTIAL_CONTENT = 206,
  HTTP_STATUS_MULTI_STATUS = 207,
  HTTP_STATUS_ALREADY_REPORTED = 208,
  HTTP_STATUS_TRANSFORMATION_APPLIED = 214,
  HTTP_STATUS_IM_USED = 226,
  HTTP_STATUS_MISCELLANEOUS_PERSISTENT_WARNING = 299,
  HTTP_STATUS_MULTIPLE_CHOICES = 300,
  HTTP_STATUS_MOVED_PERMANENTLY = 301,
  HTTP_STATUS_FOUND = 302,
  HTTP_STATUS_SEE_OTHER = 303,
  HTTP_STATUS_NOT_MODIFIED = 304,
  HTTP_STATUS_USE_PROXY = 305,
  HTTP_STATUS_SWITCH_PROXY = 306,
  HTTP_STATUS_TEMPORARY_REDIRECT = 307,
  HTTP_STATUS_PERMANENT_REDIRECT = 308,
  HTTP_STATUS_BAD_REQUEST = 400,
  HTTP_STATUS_UNAUTHORIZED = 401,
  HTTP_STATUS_PAYMENT_REQUIRED = 402,
  HTTP_STATUS_FORBIDDEN = 403,
  HTTP_STATUS_NOT_FOUND = 404,
  HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
  HTTP_STATUS_NOT_ACCEPTABLE = 406,
  HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
  HTTP_STATUS_REQUEST_TIMEOUT = 408,
  HTTP_STATUS_CONFLICT = 409,
  HTTP_STATUS_GONE = 410,
  HTTP_STATUS_LENGTH_REQUIRED = 411,
  HTTP_STATUS_PRECONDITION_FAILED = 412,
  HTTP_STATUS_PAYLOAD_TOO_LARGE = 413,
  HTTP_STATUS_URI_TOO_LONG = 414,
  HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
  HTTP_STATUS_RANGE_NOT_SATISFIABLE = 416,
  HTTP_STATUS_EXPECTATION_FAILED = 417,
  HTTP_STATUS_IM_A_TEAPOT = 418,
  HTTP_STATUS_PAGE_EXPIRED = 419,
  HTTP_STATUS_ENHANCE_YOUR_CALM = 420,
  HTTP_STATUS_MISDIRECTED_REQUEST = 421,
  HTTP_STATUS_UNPROCESSABLE_ENTITY = 422,
  HTTP_STATUS_LOCKED = 423,
  HTTP_STATUS_FAILED_DEPENDENCY = 424,
  HTTP_STATUS_TOO_EARLY = 425,
  HTTP_STATUS_UPGRADE_REQUIRED = 426,
  HTTP_STATUS_PRECONDITION_REQUIRED = 428,
  HTTP_STATUS_TOO_MANY_REQUESTS = 429,
  HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE_UNOFFICIAL = 430,
  HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
  HTTP_STATUS_LOGIN_TIMEOUT = 440,
  HTTP_STATUS_NO_RESPONSE = 444,
  HTTP_STATUS_RETRY_WITH = 449,
  HTTP_STATUS_BLOCKED_BY_PARENTAL_CONTROL = 450,
  HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS = 451,
  HTTP_STATUS_CLIENT_CLOSED_LOAD_BALANCED_REQUEST = 460,
  HTTP_STATUS_INVALID_X_FORWARDED_FOR = 463,
  HTTP_STATUS_REQUEST_HEADER_TOO_LARGE = 494,
  HTTP_STATUS_SSL_CERTIFICATE_ERROR = 495,
  HTTP_STATUS_SSL_CERTIFICATE_REQUIRED = 496,
  HTTP_STATUS_HTTP_REQUEST_SENT_TO_HTTPS_PORT = 497,
  HTTP_STATUS_INVALID_TOKEN = 498,
  HTTP_STATUS_CLIENT_CLOSED_REQUEST = 499,
  HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
  HTTP_STATUS_NOT_IMPLEMENTED = 501,
  HTTP_STATUS_BAD_GATEWAY = 502,
  HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
  HTTP_STATUS_GATEWAY_TIMEOUT = 504,
  HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
  HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506,
  HTTP_STATUS_INSUFFICIENT_STORAGE = 507,
  HTTP_STATUS_LOOP_DETECTED = 508,
  HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED = 509,
  HTTP_STATUS_NOT_EXTENDED = 510,
  HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511,
  HTTP_STATUS_WEB_SERVER_UNKNOWN_ERROR = 520,
  HTTP_STATUS_WEB_SERVER_IS_DOWN = 521,
  HTTP_STATUS_CONNECTION_TIMEOUT = 522,
  HTTP_STATUS_ORIGIN_IS_UNREACHABLE = 523,
  HTTP_STATUS_TIMEOUT_OCCURED = 524,
  HTTP_STATUS_SSL_HANDSHAKE_FAILED = 525,
  HTTP_STATUS_INVALID_SSL_CERTIFICATE = 526,
  HTTP_STATUS_RAILGUN_ERROR = 527,
  HTTP_STATUS_SITE_IS_OVERLOADED = 529,
  HTTP_STATUS_SITE_IS_FROZEN = 530,
  HTTP_STATUS_IDENTITY_PROVIDER_AUTHENTICATION_ERROR = 561,
  HTTP_STATUS_NETWORK_READ_TIMEOUT = 598,
  HTTP_STATUS_NETWORK_CONNECT_TIMEOUT = 599
};

struct mender_http_client {
    /*
     * mender_http_client_begin
     *   - 0-terminated copies of url-parts, but buf_offset will be respected
     * while receiving headers
     *   - 0-terminated copies of received headers, buf_offset must be 0
     * while sending the request and receiving the response body:
     *   - free for use by the library user
     */
    struct mender_stack *stack;

    /* socket receive buffer */
    uint8_t inbuf[CONFIG_MENDER_HTTP_RECV_BUFFER_SZ];

    /* client config */
    http_parser_settings parser_settings;
    struct mender_http_transport *transport_tcp;
    struct mender_http_transport *transport_ssl;
    struct mender_http_transport_cb transport_cb;

    /* connection info */
    http_parser parser;
    struct mender_http_transport *transport_active;
    mender_err_t internal_error;

    /* user callback */
    struct mender_http_callback *cb;
    void *cb_ctx;

    /* our state/parsing info */
    int in_callback;
    enum mender_http_state state;
    char *http_field;
    size_t http_field_size;
    char *http_value;
    size_t http_value_size;

    char *host;
    size_t host_len;
    const char *smethod;
    const char *url;
    struct http_parser_url purl;
};

struct mender_http_callback {
    void (*hdr_item_received)(void *ctx, struct mender_http_client *c,
        const char *key, const char *value, size_t valuelen);
    void (*hdr_ended)(void *ctx, struct mender_http_client *c);
    void (*body_received_chunk)(void *ctx, struct mender_http_client *c,
        const void *data, size_t len);
    void (*body_ended)(void *ctx, struct mender_http_client *c);
    void (*closed)(void *ctx, struct mender_http_client *c,
        enum mender_http_close_reason reason);
    void (*data_sent)(void *ctx, struct mender_http_client *c);
};

mender_err_t mender_http_client_create(struct mender_http_client *c, struct mender_stack *stack,
        struct mender_http_transport *tcp, struct mender_http_transport *ssl);

mender_err_t mender_http_client_begin(struct mender_http_client *c, enum mender_http_method method,
        const char *url, struct mender_http_callback *cb, void *cbctx);
void mender_http_client_send_data(struct mender_http_client *c,
        const void *data, size_t len);
void mender_http_client_send_str(struct mender_http_client *c, const char *s);
void mender_http_client_send_fmt(struct mender_http_client *c, const char *fmt, ...);
void mender_http_client_finish_header(struct mender_http_client *c);
void mender_http_client_start_receiving(struct mender_http_client *c);
mender_err_t mender_http_client_close(struct mender_http_client *c);
mender_err_t mender_http_client_end(struct mender_http_client *c);

void mender_http_client_body_received_chunk_default(void *ctx, struct mender_http_client *c,
    const void *data, size_t len);
void mender_http_client_body_ended_default(void *ctx, struct mender_http_client *c);

static inline void* mender_httpbuf_take(struct mender_http_client *c, size_t n) {
    return mender_stack_take((c->stack), n);
}

static inline void mender_httpbuf_give(struct mender_http_client *c, void *p, size_t n) {
    mender_stack_give((c->stack), p, n);
}

static inline size_t mender_httpbuf_num_total(struct mender_http_client *c) {
    return mender_stack_num_total((c->stack));
}

static inline size_t mender_httpbuf_num_free(struct mender_http_client *c) {
    return mender_stack_num_free((c->stack));
}

static inline size_t mender_httpbuf_num_used(struct mender_http_client *c) {
    return mender_stack_num_used((c->stack));
}

static inline void* mender_httpbuf_current(struct mender_http_client *c) {
    return mender_stack_current((c->stack));
}

static inline void* mender_httpbuf_base(struct mender_http_client *c) {
    return mender_stack_base((c->stack));
}

static inline void mender_httpbuf_give_all(struct mender_http_client *c) {
    mender_httpbuf_give(c, mender_httpbuf_base(c), mender_httpbuf_num_used(c));
}

#endif /* MENDER_HTTP_H */
