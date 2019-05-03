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
#include <mender/client.h>
#include <mender/client_auth.h>
#include <mender/platform/log.h>
#include <mender/identity_data.h>
#include <mender/utils.h>
#include <mender/authmgr.h>
#include <mender/internal/compiler.h>

static void mender_client_auth_reset(struct mender_client_auth *ca) {
    ca->url = NULL;
    ca->url_len = 0;
    ca->authdata = NULL;
    ca->authdata_len = 0;
    ca->data = NULL;
    ca->data_len = 0;
    ca->sig = NULL;
    ca->sig_len = 0;
    ca->token = NULL;
    ca->token_len = 0;

    ca->cb = NULL;
    ca->cbctx = NULL;

    ca->state = MENDER_CLIENT_AUTH_STATE_READY;
}

static void data_sent(void *ctx, struct mender_http_client *c) {
    struct mender_client_auth *ca = ctx;
    mender_err_t err;

    switch (ca->state) {
    case MENDER_CLIENT_AUTH_STATE_CONNECT:
        mender_httpbuf_give(c, ca->url, ca->url_len);
        ca->url = NULL;
        ca->url_len = 0;

        /* generate auth data */
        ca->authdata = mender_httpbuf_current(c);
        err = mender_authmgr_generate_authdata(ca->authmgr, ca->authdata,
            mender_httpbuf_num_free(c),
            &ca->authdata_len, &ca->data, &ca->data_len, &ca->sig, &ca->sig_len, &ca->token, &ca->token_len);
        if (err || mender_httpbuf_take(c, ca->authdata_len) != ca->authdata) {
            mender_http_client_close(c);
            return;
        }

        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_CONTENT_TYPE;
        mender_http_client_send_str(c, "Content-Type: application/json\r\n");
        break;

    case MENDER_CLIENT_AUTH_STATE_SEND_CONTENT_TYPE:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_CONTENT_LENGTH;
        mender_http_client_send_fmt(c, "Content-Length: %u\r\n", ca->data_len);
        break;

    /* send token header */
    case MENDER_CLIENT_AUTH_STATE_SEND_CONTENT_LENGTH:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_BEARER_KEY;
        mender_http_client_send_str(c, "Authorization: Bearer ");
        break;

    case MENDER_CLIENT_AUTH_STATE_SEND_BEARER_KEY:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_BEARER_VALUE;
        mender_http_client_send_data(c, ca->token, ca->token_len);
        break;

    case MENDER_CLIENT_AUTH_STATE_SEND_BEARER_VALUE:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_BEARER_END;
        mender_http_client_send_str(c, "\r\n");
        break;

    /* send signature header */
    case MENDER_CLIENT_AUTH_STATE_SEND_BEARER_END:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_SIG_KEY;
        mender_http_client_send_str(c, "X-MEN-Signature: ");
        break;

    case MENDER_CLIENT_AUTH_STATE_SEND_SIG_KEY:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_SIG_VALUE;
        mender_http_client_send_data(c, ca->sig, ca->sig_len);
        break;

    case MENDER_CLIENT_AUTH_STATE_SEND_SIG_VALUE:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_SIG_END;
        mender_http_client_send_str(c, "\r\n");
        break;

    /* finish header */
    case MENDER_CLIENT_AUTH_STATE_SEND_SIG_END:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_HDR_END;
        mender_http_client_finish_header(c);
        break;

    /* send data */
    case MENDER_CLIENT_AUTH_STATE_SEND_HDR_END:
        ca->state = MENDER_CLIENT_AUTH_STATE_SEND_DATA;
        mender_http_client_send_data(c, ca->data, ca->data_len);
        break;

    case MENDER_CLIENT_AUTH_STATE_SEND_DATA:
        mender_httpbuf_give(c, ca->authdata, ca->authdata_len);
        ca->authdata = NULL;
        ca->authdata_len = 0;
        ca->data = NULL;
        ca->data_len = 0;
        ca->sig = NULL;
        ca->sig_len = 0;
        ca->token = NULL;
        ca->token_len = 0;

        ca->state = MENDER_CLIENT_AUTH_STATE_WAIT_FOR_RESPONSE;
        mender_http_client_start_receiving(c);
        break;

    default:
        LOGE("invalid state: %d", ca->state);
        mender_http_client_close(c);
        break;
    }
}

static void hdr_ended(void *ctx __unused, struct mender_http_client *c) {
    switch (c->parser.status_code) {
    case HTTP_STATUS_OK:
        /* keep going */
        break;
    case HTTP_STATUS_UNAUTHORIZED:
        /* unauthorized */
        mender_http_client_close(c);
        break;
    default:
        /* unexpected */
        LOGE("unexpected authorization status %d", c->parser.status_code);
        mender_http_client_close(c);
        break;
    }
}

static void closed(void *ctx, struct mender_http_client *c,
    enum mender_http_close_reason reason)
{
    mender_err_t cbret;
    struct mender_client_auth *ca = ctx;

    if (ca->state == MENDER_CLIENT_AUTH_STATE_WAIT_FOR_RESPONSE && reason == MENDER_HTTP_CR_CLOSED) {
        if (c->parser.status_code == HTTP_STATUS_UNAUTHORIZED)
            cbret = MERR_CLIENT_UNAUTHORIZED;
        else if(c->parser.status_code == HTTP_STATUS_OK && mender_httpbuf_num_used(c))
            cbret = MERR_NONE;
        else
            cbret = MERR_INVALID_HTTP_STATUS;
    }
    else if(ca->state == MENDER_CLIENT_AUTH_STATE_CONNECT && reason == MENDER_HTTP_CR_INTERNAL_ERROR) {
        cbret = c->internal_error;
    }
    else {
        cbret = MERR_INVALID_STATE;
    }


    ca->state = MENDER_CLIENT_AUTH_STATE_IN_CALLBACK;
    if (ca->cb) {
        if (cbret == MERR_NONE) {
            ca->cb(ca->cbctx, cbret, mender_httpbuf_base(c), mender_httpbuf_num_used(c));
        }
        else {
            ca->cb(ca->cbctx, cbret, NULL, 0);
        }
    }
    else {
        mender_client_auth_finish_request(ca);
    }
}

static struct mender_http_callback ca_http_cb = {
    .data_sent = data_sent,
    .hdr_ended = hdr_ended,
    .body_received_chunk = mender_http_client_body_received_chunk_default,
    .body_ended = mender_http_client_body_ended_default,
    .closed = closed,
};

mender_err_t mender_client_auth_request(struct mender_client_auth *ca, const char *server,
        mender_client_auth_cb_t cb, void *cbctx)
{
    mender_err_t err;
    struct mender_http_client *client = ca->client;
    char *url;
    size_t url_len;

    if (ca->state != MENDER_CLIENT_AUTH_STATE_READY) {
        LOGE("another auth request is already running");
        return MERR_BUSY;
    }

    url = mender_httpbuf_current(client);
    err = mender_client_build_api_url(url, mender_httpbuf_num_free(client), &url_len,
        server, "/authentication/auth_requests");
    if (err) {
        return err;
    }
    if (mender_httpbuf_take(client, url_len) != url) {
        return MERR_OUT_OF_RESOURCES;
    }

    ca->url = url;
    ca->url_len = url_len;
    ca->cb = cb;
    ca->cbctx = cbctx;
    ca->state = MENDER_CLIENT_AUTH_STATE_CONNECT;

    /* open connection */
    err = mender_http_client_begin(client, MENDER_HTTP_METHOD_POST, ca->url, &ca_http_cb, ca);
    if (err) {
        mender_httpbuf_give(client, ca->url, ca->authdata_len);
        mender_client_auth_reset(ca);
        return err;
    }

    return MERR_NONE;
}

void mender_client_auth_finish_request(struct mender_client_auth *ca)
{
    mender_err_t merr;
    struct mender_http_client *client = ca->client;

    if (ca->state != MENDER_CLIENT_AUTH_STATE_IN_CALLBACK) {
        LOGE("invalid call to %s", __func__);
        return;
    }

    mender_httpbuf_give_all(client);
    merr = mender_http_client_end(client);
    if (merr) {
        LOGE("can't end http client: %x", merr);
    }

    mender_client_auth_reset(ca);
}

void mender_client_auth_create(struct mender_client_auth *ca, struct mender_http_client *client,
        struct mender_authmgr *authmgr)
{
    memset(ca, 0, sizeof(*ca));

    ca->client = client;
    ca->authmgr = authmgr;
}
