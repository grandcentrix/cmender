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
#include <mender/client_update.h>
#include <mender/platform/log.h>
#include <mender/utils.h>
#include <mender/internal/compiler.h>

static void hdr_ended(void *ctx, struct mender_http_client *c) {
    struct mender_client_update *u = ctx;
    mender_err_t merr;

    switch (c->parser.status_code) {
    case HTTP_STATUS_OK:
        /* keep going */
        merr = u->u.fetch.cb->on_init_success(u->u.fetch.cbctx);
        if (merr) {
            mender_http_client_close(c);
        }
        break;
    default:
        mender_http_client_close(c);
        break;
    }
}

static void closed(void *ctx, struct mender_http_client *c,
    enum mender_http_close_reason reason)
{
    mender_err_t merr;
    mender_err_t cbret;
    struct mender_client_update *u = ctx;

    if (u->req_ctx.state == MENDER_CLIENT_REQ_STATE_WAIT_FOR_RESPONSE && reason == MENDER_HTTP_CR_CLOSED) {
        if (c->parser.status_code == HTTP_STATUS_UNAUTHORIZED) {
            LOGW("Client not authorized to get update info.");
            cbret = MERR_CLIENT_UNAUTHORIZED;
        }
        else if (c->parser.status_code != HTTP_STATUS_OK) {
            LOGE("Error fetching scheduled update info: code (%u)", c->parser.status_code);
            cbret = MERR_INVALID_HTTP_STATUS;
        }
        else {
            LOGD("Received fetch update response");
            cbret = MERR_NONE;
        }
    }
    else if(u->req_ctx.state == MENDER_CLIENT_REQ_STATE_CONNECT && reason == MENDER_HTTP_CR_INTERNAL_ERROR) {
        cbret = c->internal_error;
    }
    else {
        cbret = MERR_INVALID_STATE;
    }

    /* nothing to receive */
    if (cbret) {
        goto do_finish_callback;
    }

    cbret = MERR_NONE;

do_finish_callback:
    merr = mender_http_client_end(u->req_ctx.client);
    if (merr) {
        LOGE("can't end http client: %x", merr);
    }

    if (u->u.fetch.cb) {
        struct mender_client_update_fetch_cb *cb = u->u.fetch.cb;
        void *cbctx = u->u.fetch.cbctx;

        /* from this point on, new requests can be made */
        mender_client_update_reset(u);

        cb->on_finish(cbctx, cbret);
    }
    else {
        mender_client_update_reset(u);
    }
}

static void body_received_chunk(void *ctx, struct mender_http_client *c, const void *data, size_t len) {
    struct mender_client_update *u = ctx;
    mender_err_t merr;

    merr = u->u.fetch.cb->on_data(u->u.fetch.cbctx, data, len);
    if (merr) {
        mender_http_client_close(c);
    }
}

static void body_ended(void *ctx __unused, struct mender_http_client *c) {
    mender_err_t merr;

    merr = mender_http_client_close(c);
    if (merr) {
        LOGE("can't close client: %x", merr);
    }
}

static struct mender_http_callback u_http_cb = {
    .data_sent = mender_client_update_data_sent,
    .hdr_ended = hdr_ended,
    .body_received_chunk = body_received_chunk,
    .body_ended = body_ended,
    .closed = closed,
};

mender_err_t mender_client_update_fetch(struct mender_client_update *u, const char *url,
        mender_duration_t max_wait __unused,
        struct mender_client_update_fetch_cb *cb, void *cbctx)
{
    mender_err_t err;
    struct mender_http_client *client = u->req_ctx.client;

    /* TODO: the update should be resumable, this would also use 'max_wait' */

    if (u->req_ctx.state != MENDER_CLIENT_REQ_STATE_READY) {
        LOGE("another update check is already running");
        return MERR_BUSY;
    }

    u->req_ctx.state = MENDER_CLIENT_REQ_STATE_CONNECT;
    u->req_ctx.sendbearer = false;

    u->u.fetch.cb = cb;
    u->u.fetch.cbctx = cbctx;

    /* open connection */
    err = mender_http_client_begin(client, MENDER_HTTP_METHOD_GET, url, &u_http_cb, u);
    if (err) {
        return err;
    }

    return MERR_NONE;
}
