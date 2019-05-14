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

#include <mender/http.h>
#include <mender/platform/log.h>
#include <mender/internal/compiler.h>
#include <mender/hexdump.h>

static void mender_http_client_cb_on_connected(void *ctx);
static void mender_http_client_cb_data_available(void *ctx);
static void mender_http_client_cb_data_sent(void *ctx);
static void mender_http_client_cb_on_error(void *ctx, mender_err_t err);

static inline mender_err_t url_copy_to_buf(struct mender_http_client *c, const char *url,
        struct http_parser_url *u, enum http_parser_url_fields f, size_t *pactual)
{
    char *buf = mender_httpbuf_take(c, u->field_data[f].len + 1);
    if (!buf) return MERR_OUT_OF_RESOURCES;

    memcpy(buf, url + u->field_data[f].off, u->field_data[f].len);
    buf[u->field_data[f].len] = '\0';

    *pactual = u->field_data[f].len + 1;
    return MERR_NONE;
}

static int data2cache(struct mender_http_client *c, const char *at, size_t length) {
    void *buf = mender_httpbuf_take(c, length);
    if (!buf) {
        LOGE("no space left to receive data");
        return 1;
    }

    memcpy(buf, at, length);
    return 0;
}

static int finish_value(struct mender_http_client *c) {
    int ret = 1;

    if (!c->http_field || !c->http_value || c->http_field_size == 0) {
        LOGE("invalid state for finish_value");
        return 1;
    }

    if (mender_httpbuf_current(c) == c->http_value || c->http_value_size == 0) {
        LOGW("got field without value");
        c->http_value = NULL;
        c->http_value_size = 0;
    }
    else {
        char *term = mender_httpbuf_take(c, 1);
        if (!term) {
            LOGE("no space left for 0-terminator after header value");
            goto out_free_hdr;
        }
        c->http_value_size++;

        *term = '\0';
    }

    if (c->cb->hdr_item_received) {
        c->cb->hdr_item_received(c->cb_ctx, c, c->http_field, c->http_value, c->http_value_size);

        if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
            goto out_free_hdr;
    }

    ret = 0;
    c->state = MENDER_HTTP_STATE_READ_HDR_FIELD;

out_free_hdr:
    if (c->http_value && c->http_value_size)
        mender_httpbuf_give(c, c->http_value, c->http_value_size);
    if (c->http_field && c->http_field_size)
        mender_httpbuf_give(c, c->http_field, c->http_field_size);

    c->http_field = mender_httpbuf_current(c);
    c->http_field_size = 0;
    c->http_value = NULL;
    c->http_value_size = 0;

    return ret;
}

static int mender_http_client_on_message_begin(http_parser *parser) {
    struct mender_http_client *c = parser->data;

    if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
        return 1;

    if (c->state != MENDER_HTTP_STATE_READ_HDR_FIELD) {
        /* this should never happen */
        LOGE("invalid state: %d", c->state);
        return 1;
    }

    return 0;
}

static int mender_http_client_on_header_field(http_parser *parser, const char *at, size_t length) {
    struct mender_http_client *c = parser->data;
    int rc;
    mender_err_t err;

    /* LOGD("FIELD(%zu)", length); */

    if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
        return 1;

    if (c->state == MENDER_HTTP_STATE_READ_HDR_FIELD) {
        /* this is the first field or the first callback after finishing the previous field */
        /* keep on going */
    }
    else if (c->state == MENDER_HTTP_STATE_READ_HDR_VALUE) {
        /* this is the first field chunk after a value */

        rc = finish_value(c);
        if (rc) {
            return rc;
        }
    }
    else {
        LOGE("invalid state: %d", c->state);
        return 1;
    }

    err = data2cache(c, at, length);
    if (err)
        return err;

    c->http_field_size += length;

    return MERR_NONE;
}

static int mender_http_client_on_header_value(http_parser *parser, const char *at, size_t length) {
    struct mender_http_client *c = parser->data;
    mender_err_t err;

    /* LOGD("VALUE(%zu)", length); */

    if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
        return 1;

    if (c->state == MENDER_HTTP_STATE_READ_HDR_VALUE) {
        /* this not the first chunk for the value */
        /* keep on going */
    }
    else if (c->state == MENDER_HTTP_STATE_READ_HDR_FIELD) {
        char *term;

        /* this is the first value chunk after a field */

        if (mender_httpbuf_current(c) == c->http_field || c->http_field_size == 0) {
            LOGE("got header value without field");
            return 1;
        }

        term = mender_httpbuf_take(c, 1);
        if (!term) {
            LOGE("no space left for 0-terminator after header value");
            return 1;
        }
        c->http_field_size++;

        *term = '\0';

        c->http_value = mender_httpbuf_current(c);
        c->http_value_size = 0;
        c->state = MENDER_HTTP_STATE_READ_HDR_VALUE;
    }
    else {
        LOGE("invalid state: %d", c->state);
        return 1;
    }

    err = data2cache(c, at, length);
    if (err)
        return err;

    c->http_value_size += length;

    return MERR_NONE;
}

static int mender_http_client_on_headers_complete(http_parser *parser) {
    struct mender_http_client *c = parser->data;
    int rc;

    if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
        return 1;

    if (c->state != MENDER_HTTP_STATE_READ_HDR_VALUE) {
        /* this should never happen */
        LOGE("invalid state: %d", c->state);
        return 1;
    }

    rc = finish_value(c);
    if (rc) {
        return rc;
    }

    if (c->cb->hdr_ended) {
        c->cb->hdr_ended(c->cb_ctx, c);

        if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
            return 1;
    }

    return 0;
}

static int mender_http_client_on_body(http_parser *parser, const char *at, size_t length) {
    struct mender_http_client *c = parser->data;

    if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
        return 1;

    if (c->cb->body_received_chunk) {
        c->cb->body_received_chunk(c->cb_ctx, c, at, length);

        if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
            return 1;
    }

    return 0;
}

static int mender_http_client_on_message_complete(http_parser *parser) {
    struct mender_http_client *c = parser->data;
    mender_err_t merr;

    if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
        return 1;

    if (c->cb->body_ended) {
        c->cb->body_ended(c->cb_ctx, c);

        if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED)
            return 1;
    }

    if (!http_should_keep_alive(parser) && c->state != MENDER_HTTP_STATE_CLOSED) {
        merr = mender_http_client_close(c);
        if (merr) {
            LOGE("can't auto-close connection");
        }
    }

    return 0;
}

mender_err_t mender_http_client_create(struct mender_http_client *c, struct mender_stack *stack,
        struct mender_http_transport *tcp, struct mender_http_transport *ssl)
{
    c->stack = stack;
    c->state = MENDER_HTTP_STATE_INITIALIZED;
    http_parser_settings_init(&c->parser_settings);
    c->parser_settings.on_message_begin = mender_http_client_on_message_begin;
    c->parser_settings.on_header_field = mender_http_client_on_header_field;
    c->parser_settings.on_header_value = mender_http_client_on_header_value;
    c->parser_settings.on_headers_complete = mender_http_client_on_headers_complete;
    c->parser_settings.on_body = mender_http_client_on_body;
    c->parser_settings.on_message_complete = mender_http_client_on_message_complete;
    c->parser.data = c;

    c->transport_cb.on_connected = mender_http_client_cb_on_connected;
    c->transport_cb.data_available = mender_http_client_cb_data_available;
    c->transport_cb.data_sent = mender_http_client_cb_data_sent;
    c->transport_cb.on_error = mender_http_client_cb_on_error;

    c->transport_tcp = tcp;
    if (c->transport_tcp) {
        c->transport_tcp->cb = &c->transport_cb;
        c->transport_tcp->cb_ctx = c;
    }

    c->transport_ssl = ssl;
    if (c->transport_ssl) {
        c->transport_ssl->cb = &c->transport_cb;
        c->transport_ssl->cb_ctx = c;
    }

    return MERR_NONE;
}

mender_err_t mender_http_client_begin(struct mender_http_client *c, enum mender_http_method method,
        const char *url, struct mender_http_callback *cb, void *cbctx)
{
    int rc;
    int port;
    size_t nbytes;
    char *host;
    const char *smethod;
    mender_err_t merr;

    if (c->state != MENDER_HTTP_STATE_INITIALIZED) {
        LOGE("http client is still running a request");
        return MERR_BUSY;
    }

    switch(method) {
        case MENDER_HTTP_METHOD_GET:
            smethod = "GET ";
            break;
        case MENDER_HTTP_METHOD_POST:
            smethod = "POST ";
            break;
        case MENDER_HTTP_METHOD_PUT:
            smethod = "PUT ";
            break;
        case MENDER_HTTP_METHOD_PATCH:
            smethod = "PATCH ";
            break;
        default:
            LOGE("unsupported method: %d", method);
            return MERR_INVALID_ARGUMENTS;
    }

    http_parser_url_init(&c->purl);

    /* parse url */
    rc = http_parser_parse_url(url, strlen(url), 0, &c->purl);
    if (rc) {
        LOGE("can't parse url: %s", url);
        return MERR_INVALID_ARGUMENTS;
    }

    /* get protocol */
    if (c->purl.field_data[UF_SCHEMA].len) {
        char *schema = mender_httpbuf_current(c);
        merr = url_copy_to_buf(c, url, &c->purl, UF_SCHEMA, &nbytes);
        if (merr) {
            LOGE("failed to copy url to buf");
            return merr;
        }

        if (strcasecmp(schema, "http") == 0) {
            c->transport_active = c->transport_tcp;
            port = 80;
        }
        else if (strcasecmp(schema, "https") == 0) {
            c->transport_active = c->transport_ssl;
            port = 443;
        }
        else {
            LOGE("unsupported schema: %s", schema);
            mender_httpbuf_give(c, schema, nbytes);
            return MERR_INVALID_ARGUMENTS;
        }
        mender_httpbuf_give(c, schema, nbytes);
    }
    else {
        c->transport_active = c->transport_tcp;
        port = 80;
    }

    if (!c->transport_active) {
        LOGE("no valid transport found");
        return MERR_NO_HTTP_TRANSPORT;
    }

    /* get port */
    if (c->purl.field_data[UF_PORT].len) {
        port = c->purl.port;
    }

    /* get 0-terminated copy of host */
    host = mender_httpbuf_current(c);
    if (!c->purl.field_data[UF_HOST].len) {
        LOGE("URL has no host");
        return MERR_INVALID_ARGUMENTS;
    }
    merr = url_copy_to_buf(c, url, &c->purl, UF_HOST, &nbytes);
    if (merr) {
        return merr;
    }

    /* we can't read the response while sending the request */
    c->transport_active->set_read_cb_enabled(c->transport_active, 0);

    http_parser_init(&c->parser, HTTP_RESPONSE);
    c->cb = cb;
    c->cb_ctx = cbctx;
    c->state = MENDER_HTTP_STATE_CONNECT;
    c->host = host;
    c->host_len = nbytes;
    c->url = url;
    c->smethod = smethod;
    c->http_field = NULL;
    c->http_field_size = 0;
    c->http_value = NULL;
    c->http_value_size = 0;

    c->transport_active->connect(c->transport_active, host, port, 30000);

    return MERR_NONE;
}

void mender_http_client_send_data(struct mender_http_client *c,
        const void *data, size_t len)
{
    c->transport_active->write(c->transport_active, data, len);
}

void mender_http_client_send_str(struct mender_http_client *c, const char *s)
{
    c->transport_active->write(c->transport_active, s, strlen(s));
}

void mender_http_client_send_fmt(struct mender_http_client *c,
        const char *fmt, ...)
{
    int rc;
    size_t maxlen = mender_httpbuf_num_free(c);
    char *buf = mender_httpbuf_current(c);
    mender_err_t err;

    va_list ap;
    va_start(ap, fmt);
    rc = vsnprintf(buf, maxlen, fmt, ap);
    va_end(ap);

    if (rc < 0 || rc >= (int)maxlen) {
        c->internal_error = MERR_OUT_OF_RESOURCES;
        err = mender_http_client_close(c);
        if (err) {
            LOGE("can't close connection");
        }
        return;
    }

    c->transport_active->write(c->transport_active, buf, rc);
}

void mender_http_client_finish_header(struct mender_http_client *c)
{
    mender_http_client_send_data(c, "\r\n", 2);
}

void mender_http_client_start_receiving(struct mender_http_client *c)
{
    c->state = MENDER_HTTP_STATE_READ_HDR_FIELD;
    c->http_field = mender_httpbuf_current(c);
    c->http_field_size = 0;
    c->http_value = NULL;
    c->http_value_size = 0;
    c->transport_active->set_read_cb_enabled(c->transport_active, 1);
}

mender_err_t mender_http_client_close(struct mender_http_client *c) {
    enum mender_http_state oldstate;

    if (c->state == MENDER_HTTP_STATE_INITIALIZED) {
        LOGE("close called without ever starting a request");
        return MERR_INVALID_STATE;
    }

    if (c->state == MENDER_HTTP_STATE_CLOSED) {
        return MERR_NONE;
    }

    if (c->in_callback) {
        c->state = MENDER_HTTP_STATE_CLOSE_REQUESTED;

        /* if we weren't in a callback, this would have succeeded */
        return MERR_NONE;
    }

    oldstate = c->state;
    c->transport_active->close(c->transport_active);
    c->state = MENDER_HTTP_STATE_CLOSED;

    if (c->cb->closed) {
        enum mender_http_close_reason reason;
        if (oldstate == MENDER_HTTP_STATE_CLOSE_REQUESTED)
            reason = MENDER_HTTP_CR_CLOSED;
        else if (c->parser.http_errno)
            reason = MENDER_HTTP_CR_PARSING_ERROR;
        else if (c->internal_error)
            reason = MENDER_HTTP_CR_INTERNAL_ERROR;
        else
            reason = MENDER_HTTP_CR_CLOSED;

        c->cb->closed(c->cb_ctx, c, reason);
    }

    return MERR_NONE;
}

mender_err_t mender_http_client_end(struct mender_http_client *c) {
    if (c->state == MENDER_HTTP_STATE_INITIALIZED) {
        LOGW("no request running");
        return MERR_NONE;
    }

    if (c->state != MENDER_HTTP_STATE_CLOSED) {
        LOGE("can't end an active request. state: %d", c->state);
        return MERR_INVALID_STATE;
    }

    c->internal_error = MERR_NONE;
    c->state = MENDER_HTTP_STATE_INITIALIZED;
    return MERR_NONE;
}

static void mender_http_client_cb_on_connected(void *ctx) {
    struct mender_http_client *c = ctx;

    c->state = MENDER_HTTP_STATE_CONNECTED;

    mender_http_client_cb_data_sent(ctx);
}

static void mender_http_client_cb_data_available(void *ctx) {
    struct mender_http_client *c = ctx;
    size_t nbytes;
    int rc;
    mender_err_t merr;

    merr = c->transport_active->read(c->transport_active, c->inbuf, ARRAY_SIZE(c->inbuf), &nbytes);
    if (merr) {
        if (MENDER_ERR_VAL(merr) != MERR_TRY_AGAIN) {
            LOGE("transport read error: %d", merr);

            c->internal_error = merr;
            merr = mender_http_client_close(c);
            if (merr) {
                LOGE("can't close connection");
            }
        }
        return;
    }

    if (nbytes == 0) {
        LOGD("server closed the connection");
        merr = mender_http_client_close(c);
        if (merr) {
            LOGE("can't close connection");
        }
        return;
    }

    c->in_callback = 1;
    rc = http_parser_execute(&c->parser, &c->parser_settings, (const char *)c->inbuf, nbytes);
    c->in_callback = 0;

    if (c->state == MENDER_HTTP_STATE_CLOSE_REQUESTED) {
        mender_http_client_close(c);
        return;
    }

    if (c->parser.http_errno) {
        LOGE("parser error: %s", http_errno_name(c->parser.http_errno));
        mender_http_client_close(c);
        return;
    }
    if (rc != (int)nbytes) {
        LOGW("parser read %d instead of %zu bytes", rc, nbytes);
    }
}

static void mender_http_client_cb_data_sent(void *ctx) {
    struct mender_http_client *c = ctx;
    mender_err_t err;

again:
    switch (c->state) {
    case MENDER_HTTP_STATE_CONNECTED: {
        mender_httpbuf_give(c, c->host, c->host_len);

        c->state = MENDER_HTTP_STATE_SEND_METHOD;
        mender_http_client_send_str(c, c->smethod);
        break;
    }

    /*
     * {METHOD} {PATH} HTTP/1.1\r\n
     */
    case MENDER_HTTP_STATE_SEND_METHOD:
        c->state = MENDER_HTTP_STATE_SEND_PATH;
        if (c->purl.field_data[UF_PATH].len) {
            mender_http_client_send_data(c, c->url + c->purl.field_data[UF_PATH].off,
                    c->purl.field_data[UF_PATH].len);
        }
        else {
            mender_http_client_send_data(c, "/", 1);
        }
        break;

    case MENDER_HTTP_STATE_SEND_PATH:
        if (c->purl.field_data[UF_QUERY].len) {
            c->state = MENDER_HTTP_STATE_SEND_QUERY_SEP;
            mender_http_client_send_data(c, "?", 1);
        }
        else {
            c->state = MENDER_HTTP_STATE_SEND_QUERY;
            goto again;
        }
        break;

    case MENDER_HTTP_STATE_SEND_QUERY_SEP:
        c->state = MENDER_HTTP_STATE_SEND_QUERY;
        mender_http_client_send_data(c, c->url + c->purl.field_data[UF_QUERY].off,
                c->purl.field_data[UF_QUERY].len);
        break;

    case MENDER_HTTP_STATE_SEND_QUERY:
        c->state = MENDER_HTTP_STATE_SEND_HTTPVER;
        mender_http_client_send_data(c, " HTTP/1.1\r\n", 11);
        break;

    /*
     * Host: {HOSTNAME}\r\n
     */

    case MENDER_HTTP_STATE_SEND_HTTPVER:
        c->state = MENDER_HTTP_STATE_SEND_HOST_KEY;
        mender_http_client_send_data(c, "Host: ", 6);
        break;

    case MENDER_HTTP_STATE_SEND_HOST_KEY:
        c->state = MENDER_HTTP_STATE_SEND_HOST_NAME;
        mender_http_client_send_data(c, c->url + c->purl.field_data[UF_HOST].off,
            c->purl.field_data[UF_HOST].len);
        break;

    case MENDER_HTTP_STATE_SEND_HOST_NAME:
        if (c->purl.field_data[UF_PORT].len) {
            c->state = MENDER_HTTP_STATE_SEND_HOST_COLON;
            mender_http_client_send_data(c, ":", 1);
        }
        else {
            c->state = MENDER_HTTP_STATE_SEND_HOST_PORT;
            goto again;
        }
        break;

    case MENDER_HTTP_STATE_SEND_HOST_COLON:
        c->state = MENDER_HTTP_STATE_SEND_HOST_PORT;
        mender_http_client_send_data(c, c->url + c->purl.field_data[UF_PORT].off,
            c->purl.field_data[UF_PORT].len);
        break;

    case MENDER_HTTP_STATE_SEND_HOST_PORT:
        c->state = MENDER_HTTP_STATE_SEND_HOST_END;
        mender_http_client_send_data(c, "\r\n", 2);
        break;

    case MENDER_HTTP_STATE_SEND_HOST_END:
        c->state = MENDER_HTTP_STATE_SEND_USER_HDR;
        goto again;

    case MENDER_HTTP_STATE_SEND_USER_HDR:
    case MENDER_HTTP_STATE_READ_HDR_FIELD:
    case MENDER_HTTP_STATE_READ_HDR_VALUE:
        if (c->cb->data_sent) {
            c->cb->data_sent(c->cb_ctx, c);
        }
        break;

    default:
        LOGE("invalid state: %d", c->state);

        c->internal_error = MERR_INVALID_STATE;
        err = mender_http_client_close(c);
        if (err) {
            LOGE("can't close connection");
        }
        break;
    }
}

static void mender_http_client_cb_on_error(void *ctx, mender_err_t err) {
    struct mender_http_client *c = ctx;

    LOGE("transport error: %d", err);

    c->internal_error = err;
    err = mender_http_client_close(c);
    if (err) {
        LOGE("can't close connection");
    }
}

void mender_http_client_body_received_chunk_default(void *ctx __unused,
    struct mender_http_client *c, const void *data, size_t len)
{
    void *buf = mender_httpbuf_take(c, len);
    if (!buf) {
        LOGE("token is too big for our buffer");
        mender_http_client_close(c);
        return;
    }

    memcpy(buf, data, len);
}

void mender_http_client_body_ended_default(void *ctx __unused, struct mender_http_client *c)
{
    mender_err_t merr;

    merr = mender_http_client_close(c);
    if (merr) {
        LOGE("can't close client: %x", merr);
    }
}
