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
#include <mender/client_status.h>
#include <mender/platform/log.h>
#include <mender/utils.h>
#include <mender/internal/compiler.h>

static void mender_client_status_reset(struct mender_client_status *s) {
    s->cb = NULL;
    s->cbctx = NULL;

    s->deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;
    s->url = NULL;
    s->url_len = 0;

    mender_client_req_ctx_reset(&s->req_ctx);
}

static void data_sent(void *ctx, struct mender_http_client *c) {
    struct mender_client_status *s = ctx;
    mender_err_t err;

    do {
        switch (s->req_ctx.state) {
        case MENDER_CLIENT_REQ_STATE_CONNECT:
            mender_httpbuf_give(c, s->url, s->url_len);
            s->url = NULL;
            s->url_len = 0;
            break;

        case MENDER_CLIENT_REQ_STATE_SEND_BEARER_END: {
            int rc;
            char *json;
            size_t json_len;

            json = mender_httpbuf_current(c);
            rc = snprintf(json, mender_httpbuf_num_free(c), "{\"status\":\"%s\"}",
                mender_deployment_status_to_str(s->deployment_status));
            if (rc < 0 || rc >= (int)mender_httpbuf_num_free(c)) {
                mender_http_client_close(c);
                return;
            }

            json_len = (size_t) rc;
            if (mender_httpbuf_take(c, json_len) != json) {
                mender_http_client_close(c);
                return;
            }

            s->req_ctx.data = json;
            s->req_ctx.data_len = json_len;
            break;
        }

        case MENDER_CLIENT_REQ_STATE_SEND_DATA:
            mender_httpbuf_give(c, (void*)s->req_ctx.data, s->req_ctx.data_len);
            s->req_ctx.data = NULL;
            s->req_ctx.data_len = 0;
            break;

        default:
            break;
        }

        err = mender_client_req_handle_send(&s->req_ctx);
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
    struct mender_client_status *s = ctx;

    if (s->req_ctx.state == MENDER_CLIENT_REQ_STATE_WAIT_FOR_RESPONSE && reason == MENDER_HTTP_CR_CLOSED) {
        if (c->parser.status_code == HTTP_STATUS_UNAUTHORIZED)
            cbret = MERR_CLIENT_UNAUTHORIZED;
        else if(c->parser.status_code == HTTP_STATUS_CONFLICT) {
            LOGW("status report rejected, deployment aborted at the backend");
            cbret = MERR_DEPLOYMENT_ABORTED;
        }
        else if (c->parser.status_code == HTTP_STATUS_NO_CONTENT) {
            LOGD("status reported");
            cbret = MERR_NONE;
        }
        else {
            LOGE("got unexpected HTTP status when reporting status: %u", c->parser.status_code);
            cbret = MERR_INVALID_HTTP_STATUS;
        }
    }
    else if(s->req_ctx.state == MENDER_CLIENT_REQ_STATE_CONNECT && reason == MENDER_HTTP_CR_INTERNAL_ERROR) {
        cbret = c->internal_error;
    }
    else {
        cbret = MERR_INVALID_STATE;
    }

    merr = mender_http_client_end(c);
    if (merr) {
        LOGE("can't end http client: %x", merr);
    }

    if (s->cb) {
        mender_client_status_cb_t cb = s->cb;
        void *cbctx = s->cbctx;

        /* from this point on, new requests can be made */
        mender_client_status_reset(s);

        cb(cbctx, cbret);
    }
    else {
        mender_client_status_reset(s);
    }
}

static struct mender_http_callback s_http_cb = {
    .data_sent = data_sent,
    .hdr_ended = hdr_ended,
    .closed = closed,
};

mender_err_t mender_client_status_report(struct mender_client_status *s, const char *server,
        const char *deployment_id, enum mender_deployment_status status,
        mender_client_status_cb_t cb, void *cbctx)
{
    mender_err_t err;
    struct mender_http_client *client = s->req_ctx.client;
    char *url;
    size_t url_len;

    if (s->req_ctx.state != MENDER_CLIENT_REQ_STATE_READY) {
        LOGE("another status report is already running");
        return MERR_BUSY;
    }

    url = mender_httpbuf_current(client);
    err = mender_client_build_api_url_getfmt(url, mender_httpbuf_num_free(client), &url_len,
        server, "/deployments/device/deployments/%s/status", deployment_id);
    if (err) {
        return err;
    }
    if (mender_httpbuf_take(client, url_len) != url) {
        return MERR_OUT_OF_RESOURCES;
    }

    s->req_ctx.state = MENDER_CLIENT_REQ_STATE_CONNECT;

    s->deployment_status = status;
    s->cb = cb;
    s->cbctx = cbctx;
    s->url = url;
    s->url_len = url_len;

    /* open connection */
    err = mender_http_client_begin(client, MENDER_HTTP_METHOD_PUT, s->url, &s_http_cb, s);
    if (err) {
        mender_httpbuf_give(client, s->url, s->url_len);
        mender_client_status_reset(s);
        return err;
    }

    return MERR_NONE;
}

void mender_client_status_create(struct mender_client_status *s, struct mender_http_client *client,
        struct mender_authmgr *authmgr)
{
    memset(s, 0, sizeof(*s));
    mender_client_req_ctx_init(&s->req_ctx, client, authmgr);
}
