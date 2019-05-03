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
#include <mender/client_inventory.h>
#include <mender/platform/log.h>
#include <mender/utils.h>
#include <mender/internal/compiler.h>

static void mender_client_inventory_reset(struct mender_client_inventory *ic) {
    ic->cb = NULL;
    ic->cbctx = NULL;

    ic->url = NULL;
    ic->url_len = 0;

    mender_client_req_ctx_reset(&ic->req_ctx);
}

static void data_sent(void *ctx, struct mender_http_client *c) {
    struct mender_client_inventory *ic = ctx;
    mender_err_t err;

    do {
        switch (ic->req_ctx.state) {
        case MENDER_CLIENT_REQ_STATE_CONNECT:
            mender_httpbuf_give(c, ic->url, ic->url_len);
            ic->url = NULL;
            ic->url_len = 0;
            break;

        case MENDER_CLIENT_REQ_STATE_SEND_DATA:
            mender_httpbuf_give(c, (void*)ic->req_ctx.data, ic->req_ctx.data_len);
            ic->req_ctx.data = NULL;
            ic->req_ctx.data_len = 0;
            break;

        default:
            break;
        }

        err = mender_client_req_handle_send(&ic->req_ctx);
    } while (err == MERR_TRY_AGAIN);

    if (err) {
        mender_http_client_close(c);
    }
}

static void hdr_ended(void *ctx __unused, struct mender_http_client *c) {
    mender_http_client_close(c);
}

static void closed(void *ctx, struct mender_http_client *c,
    enum mender_http_close_reason reason)
{
    mender_err_t merr;
    mender_err_t cbret;
    struct mender_client_inventory *ic = ctx;

    if (ic->req_ctx.state == MENDER_CLIENT_REQ_STATE_WAIT_FOR_RESPONSE && reason == MENDER_HTTP_CR_CLOSED) {
        if (c->parser.status_code == HTTP_STATUS_UNAUTHORIZED)
            cbret = MERR_CLIENT_UNAUTHORIZED;
        else if(c->parser.status_code == HTTP_STATUS_OK)
            cbret = MERR_NONE;
        else
            cbret = MERR_INVALID_HTTP_STATUS;
    }
    else if(ic->req_ctx.state == MENDER_CLIENT_REQ_STATE_CONNECT && reason == MENDER_HTTP_CR_INTERNAL_ERROR) {
        cbret = c->internal_error;
    }
    else {
        cbret = MERR_INVALID_STATE;
    }

    merr = mender_http_client_end(c);
    if (merr) {
        LOGE("can't end http client: %x", merr);
    }

    if (ic->cb) {
        mender_client_inventory_cb_t cb = ic->cb;
        void *cbctx = ic->cbctx;

        /* from this point on, new requests can be made */
        mender_client_inventory_reset(ic);

        cb(cbctx, cbret);
    }
    else {
        mender_client_inventory_reset(ic);
    }
}

static struct mender_http_callback ic_http_cb = {
    .data_sent = data_sent,
    .hdr_ended = hdr_ended,
    .closed = closed,
};

mender_err_t mender_client_inventory_submit(struct mender_client_inventory *ic, const char *server,
        const void *data, size_t data_len,
        mender_client_inventory_cb_t cb, void *cbctx)
{
    mender_err_t err;
    struct mender_http_client *client = ic->req_ctx.client;
    char *url;
    size_t url_len;

    if (ic->req_ctx.state != MENDER_CLIENT_REQ_STATE_READY) {
        LOGE("another inventory submission is already running");
        return MERR_BUSY;
    }

    url = mender_httpbuf_current(client);
    err = mender_client_build_api_url(url, mender_httpbuf_num_free(client), &url_len,
        server, "/inventory/device/attributes");
    if (err) {
        return err;
    }
    if (mender_httpbuf_take(client, url_len) != url) {
        return MERR_OUT_OF_RESOURCES;
    }

    ic->req_ctx.state = MENDER_CLIENT_REQ_STATE_CONNECT;
    ic->req_ctx.data = data;
    ic->req_ctx.data_len = data_len;

    ic->cb = cb;
    ic->cbctx = cbctx;
    ic->url = url;
    ic->url_len = url_len;

    /* open connection */
    err = mender_http_client_begin(client, MENDER_HTTP_METHOD_PATCH, ic->url, &ic_http_cb, ic);
    if (err) {
        mender_httpbuf_give(client, ic->url, ic->url_len);
        mender_client_inventory_reset(ic);
        return err;
    }
    return MERR_NONE;
}

void mender_client_inventory_create(struct mender_client_inventory *ic, struct mender_http_client *client,
        struct mender_authmgr *authmgr)
{
    memset(ic, 0, sizeof(*ic));
    mender_client_req_ctx_init(&ic->req_ctx, client, authmgr);
}
