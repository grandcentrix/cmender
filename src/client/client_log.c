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
#include <mender/client_log.h>
#include <mender/platform/log.h>
#include <mender/utils.h>
#include <mender/internal/compiler.h>
#include <time.h>

static void mender_client_log_reset(struct mender_client_log *l) {
    l->cb = NULL;
    l->cbctx = NULL;

    l->url = NULL;
    l->url_len = 0;

    mender_client_req_ctx_reset(&l->req_ctx);
}

static void data_sent(void *ctx, struct mender_http_client *c) {
    struct mender_client_log *l = ctx;
    mender_err_t err;

    do {
        switch (l->req_ctx.state) {
        case MENDER_CLIENT_REQ_STATE_CONNECT:
            mender_httpbuf_give(c, l->url, l->url_len);
            l->url = NULL;
            l->url_len = 0;
            break;

        case MENDER_CLIENT_REQ_STATE_SEND_BEARER_END: {
            int rc;
            time_t time_now;
            struct tm *time_tm;
            char *log; size_t log_len; log = mender_httpbuf_current(c);

            time(&time_now);
            time_tm = gmtime(&time_now);

            rc = snprintf(log, mender_httpbuf_num_free(c),
                    "{\"messages\":[{\"timestamp\": \"%i-%02i-%02iT%02i:%02i:%02i.000Z\", \"level\": \"ERROR\", \"message\": \"%s\"}]}",
                    time_tm->tm_year+1900, time_tm->tm_mon+1, time_tm->tm_mday, time_tm->tm_hour, time_tm->tm_min, time_tm->tm_sec,
                    l->logs);

            if (rc < 0 || rc >= (int)mender_httpbuf_num_free(c)) {
                mender_http_client_close(c);
                return;
            }

            log_len = (size_t) rc;
            if (mender_httpbuf_take(c, log_len) != log) {
                mender_http_client_close(c);
                return;
            }

            l->req_ctx.data = log;
            l->req_ctx.data_len = log_len;
            break;
        }

        case MENDER_CLIENT_REQ_STATE_SEND_DATA:
            mender_httpbuf_give(c, (void*)l->req_ctx.data, l->req_ctx.data_len);
            l->req_ctx.data = NULL;
            l->req_ctx.data_len = 0;
            break;

        default:
            break;
        }

        err = mender_client_req_handle_send(&l->req_ctx);
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
    struct mender_client_log *l = ctx;

    if (l->req_ctx.state == MENDER_CLIENT_REQ_STATE_WAIT_FOR_RESPONSE && reason == MENDER_HTTP_CR_CLOSED) {
        if (c->parser.status_code == HTTP_STATUS_UNAUTHORIZED)
            cbret = MERR_CLIENT_UNAUTHORIZED;
        else if (c->parser.status_code == HTTP_STATUS_NO_CONTENT) {
            LOGD("log uploaded");
            cbret = MERR_NONE;
        }
        else {
            LOGE("got unexpected HTTP status when reporting status: %u", c->parser.status_code);
            cbret = MERR_INVALID_HTTP_STATUS;
        }
    }
    else if(l->req_ctx.state == MENDER_CLIENT_REQ_STATE_CONNECT && reason == MENDER_HTTP_CR_INTERNAL_ERROR) {
        cbret = c->internal_error;
    }
    else {
        cbret = MERR_INVALID_STATE;
    }

    merr = mender_http_client_end(c);
    if (merr) {
        LOGE("can't end http client: %x", merr);
    }

    if (l->cb) {
        mender_client_log_cb_t cb = l->cb;
        void *cbctx = l->cbctx;

        /* from this point on, new requests can be made */
        mender_client_log_reset(l);

        cb(cbctx, cbret);
    }
    else {
        mender_client_log_reset(l);
    }
}

static struct mender_http_callback l_http_cb = {
    .data_sent = data_sent,
    .hdr_ended = hdr_ended,
    .closed = closed,
};

mender_err_t mender_client_log_upload(struct mender_client_log *l, const char *server,
        const char *deployment_id, const char *logs,
        mender_client_log_cb_t cb, void *cbctx)
{
    mender_err_t err;
    struct mender_http_client *client = l->req_ctx.client;
    char *url;
    size_t url_len;

    if (l->req_ctx.state != MENDER_CLIENT_REQ_STATE_READY) {
        LOGE("another log report is already running");
        return MERR_BUSY;
    }

    url = mender_httpbuf_current(client);
    err = mender_client_build_api_url_getfmt(url, mender_httpbuf_num_free(client), &url_len,
        server, "/deployments/device/deployments/%s/log", deployment_id);
    if (err) {
        return err;
    }
    if (mender_httpbuf_take(client, url_len) != url) {
        return MERR_OUT_OF_RESOURCES;
    }

    l->req_ctx.state = MENDER_CLIENT_REQ_STATE_CONNECT;

    l->cb = cb;
    l->cbctx = cbctx;
    l->url = url;
    l->url_len = url_len;
    l->logs = logs;

    /* open connection */
    err = mender_http_client_begin(client, MENDER_HTTP_METHOD_PUT, l->url, &l_http_cb, l);
    if (err) {
        mender_httpbuf_give(client, l->url, l->url_len);
        mender_client_log_reset(l);
        return err;
    }

    return MERR_NONE;
}

void mender_client_log_create(struct mender_client_log *l, struct mender_http_client *client,
        struct mender_authmgr *authmgr)
{
    memset(l, 0, sizeof(*l));
    mender_client_req_ctx_init(&l->req_ctx, client, authmgr);
}
