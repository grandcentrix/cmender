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

#include <mender/client.h>
#include <mender/platform/log.h>
#include <mender/internal/compiler.h>

#define API_PREFIX "/api/devices/v1/"

static int starts_with(const char *s, const char *prefix)
{
    while (*prefix) {
        if (*prefix++ != *s++)
            return 0;
    }
    return 1;
}

mender_err_t mender_client_build_api_url(char *buf, size_t maxsz,  size_t *pactual,
        const char *server, const char *url)
{
    int rc;
    const char *schema = "";

    /* default to https */
    if (!starts_with(server, "https://") && !starts_with(server, "http://"))
        schema = "https://";

    if (url[0] == '/')
        url++;

    rc = snprintf(buf, maxsz, "%s%s%s%s", schema, server, API_PREFIX, url);
    if (rc < 0 || rc >= (int)maxsz)
        return MERR_BUFFER_TOO_SMALL;

    *pactual = (size_t)(rc) + 1;
    return MERR_NONE;
}

mender_err_t mender_client_build_api_url_getfmt(char *buf, size_t maxsz,  size_t *pactual,
        const char *server, const char *fmt, ...)
{
    int rc;
    size_t actual = 0;
    mender_err_t merr;
    va_list ap;

    if (fmt[0] == '/')
        fmt++;

    merr = mender_client_build_api_url(buf, maxsz, &actual, server, "");
    if (merr)
        return merr;

    buf += (actual - 1);
    maxsz -= (actual - 1);

    va_start(ap, fmt);
    rc = vsnprintf(buf, maxsz, fmt, ap);
    va_end(ap);

    if (rc < 0 || rc >= (int)maxsz) {
        return MERR_BUFFER_TOO_SMALL;
    }

    *pactual = (actual -1) + rc;
    return MERR_NONE;
}

/*
 * Normally one minute, but used in tests to lower the interval to avoid
 * waiting.
 */
static mender_duration_t exponential_backoff_smallest_unit = 1 * 60;

/*
 * Simple algorithm: Start with one minute, and try three times, then double
 * interval (max_interval is maximum) and try again. Repeat until we tried
 * three times with max_interval.
 */
mender_err_t mender_client_get_exponential_backoff_time(int tried,
        mender_duration_t max_interval, mender_duration_t *pduration)
{
    static const int per_interval_attempts = 3;
    int c;

    mender_duration_t interval = 1 * exponential_backoff_smallest_unit;
    mender_duration_t next_interval = interval;

    for (c = 0; c <= tried; c += per_interval_attempts) {
        interval = next_interval;
        next_interval *= 2;
        if (interval >= max_interval) {
            if (tried - c >= per_interval_attempts) {
                /*
                 * At max interval and already tried three
                 * times. Give up.
                 */
                *pduration = 0;
                LOGE("Tried maximum amount of times");
                return MERR_TIMEOUT;
            }

            /*
             * Don't use less than the smallest unit, usually one
             * minute.
             */
            if (max_interval < exponential_backoff_smallest_unit) {
                *pduration = exponential_backoff_smallest_unit;
                return MERR_NONE;
            }
            *pduration = max_interval;
            return MERR_NONE;
        }
    }

    *pduration = interval;
    return MERR_NONE;
}

const char * mender_deployment_status_to_str(enum mender_deployment_status status) {
    switch (status) {
        case MENDER_DEPLOYMENT_STATUS_INSTALLING:
            return "installing";
        case MENDER_DEPLOYMENT_STATUS_DOWNLOADING:
            return "downloading";
        case MENDER_DEPLOYMENT_STATUS_REBOOTING:
            return "rebooting";
        case MENDER_DEPLOYMENT_STATUS_SUCCESS:
            return "success";
        case MENDER_DEPLOYMENT_STATUS_FAILURE:
            return "failure";
        case MENDER_DEPLOYMENT_STATUS_ALREADY_INSTALLED:
            return "already-installed";
        default:
            return "unknown";
    }
}

void mender_client_req_ctx_init(struct mender_client_req_ctx *ctx,
    struct mender_http_client *client, struct mender_authmgr *authmgr)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->client = client;
    ctx->authmgr = authmgr;
    ctx->state = MENDER_CLIENT_REQ_STATE_READY;
}

void mender_client_req_ctx_reset(struct mender_client_req_ctx *ctx) {
    ctx->token = NULL;
    ctx->token_len = 0;
    ctx->data = NULL;
    ctx->data_len = 0;
    ctx->state = MENDER_CLIENT_REQ_STATE_READY;
}

mender_err_t mender_client_req_handle_send(struct mender_client_req_ctx *ctx) {
    mender_err_t err;

    switch (ctx->state) {
    case MENDER_CLIENT_REQ_STATE_CONNECT:
        ctx->state = MENDER_CLIENT_REQ_STATE_SEND_BEARER_KEY;
        mender_http_client_send_str(ctx->client, "Authorization: Bearer ");
        break;

    case MENDER_CLIENT_REQ_STATE_SEND_BEARER_KEY: {
        void *token;
        size_t token_len;

        token = mender_httpbuf_current(ctx->client);
        err = mender_authmgr_get_token(ctx->authmgr, token, mender_httpbuf_num_free(ctx->client), &token_len);
        if (err || mender_httpbuf_take(ctx->client, token_len) != token) {
            /* let the server tell us, that our token is invalid */
            ctx->state = MENDER_CLIENT_REQ_STATE_SEND_BEARER_VALUE;
            return MERR_TRY_AGAIN;
        }
        else {
            ctx->token = token;
            ctx->token_len = token_len;
            ctx->state = MENDER_CLIENT_REQ_STATE_SEND_BEARER_VALUE;
            mender_http_client_send_data(ctx->client, ctx->token, ctx->token_len);
        }
        break;
    }

    case MENDER_CLIENT_REQ_STATE_SEND_BEARER_VALUE:
        if (ctx->token) {
            mender_httpbuf_give(ctx->client, ctx->token, ctx->token_len);
            ctx->token = NULL;
            ctx->token_len = 0;
        }

        ctx->state = MENDER_CLIENT_REQ_STATE_SEND_BEARER_END;
        mender_http_client_send_str(ctx->client, "\r\n");
        break;

    case MENDER_CLIENT_REQ_STATE_SEND_BEARER_END:
        if (ctx->data) {
            ctx->state = MENDER_CLIENT_REQ_STATE_SEND_CONTENT_TYPE;
            mender_http_client_send_str(ctx->client, "Content-Type: application/json\r\n");
        }
        else {
            ctx->state = MENDER_CLIENT_REQ_STATE_SEND_CONTENT_LENGTH;
            return MERR_TRY_AGAIN;
        }
        break;

    case MENDER_CLIENT_REQ_STATE_SEND_CONTENT_TYPE:
        ctx->state = MENDER_CLIENT_REQ_STATE_SEND_CONTENT_LENGTH;
        mender_http_client_send_fmt(ctx->client, "Content-Length: %u\r\n", ctx->data_len);
        break;

    case MENDER_CLIENT_REQ_STATE_SEND_CONTENT_LENGTH:
        ctx->state = MENDER_CLIENT_REQ_STATE_SEND_HDR_END;
        mender_http_client_finish_header(ctx->client);
        break;

    case MENDER_CLIENT_REQ_STATE_SEND_HDR_END:
        if (ctx->data) {
            ctx->state = MENDER_CLIENT_REQ_STATE_SEND_DATA;
            mender_http_client_send_data(ctx->client, ctx->data, ctx->data_len);
        }
        else {
            ctx->state = MENDER_CLIENT_REQ_STATE_SEND_DATA;
            return MERR_TRY_AGAIN;
        }
        break;

    case MENDER_CLIENT_REQ_STATE_SEND_DATA:
        ctx->state = MENDER_CLIENT_REQ_STATE_WAIT_FOR_RESPONSE;
        mender_http_client_start_receiving(ctx->client);
        break;

    default:
        LOGE("invalid state: %d", ctx->state);
        return MERR_INVALID_STATE;
    }

    return MERR_NONE;
}
