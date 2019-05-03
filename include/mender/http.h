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
