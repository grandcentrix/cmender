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

static int jsonstrcmp(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0)
    {
        return 0;
    }
    return -1;
}

static int jsonstrlen(jsmntok_t *tok) {
    if (tok->type == JSMN_STRING) {
        return tok->end - tok->start;
    }
    return -1;
}

static size_t json_value_nchildtokens(jsmntok_t *t) {
    int i;
    size_t ntokens = 0;

    for (i = 0; i < t->size; i++) {
        ntokens++;
        ntokens += json_value_nchildtokens(t + ntokens);
    }

    return ntokens;
}

static mender_err_t jsonstrcpy(const char *json, jsmntok_t *tok, char *dst, size_t dstmax) {
    if (tok->type == JSMN_STRING) {
        int len = jsonstrlen(tok);
        if (len < 0 || len >= (int)dstmax)
            return MERR_BUFFER_TOO_SMALL;

        memcpy(dst, json + tok->start, len);
        dst[len] = '\0';

        return mender_json_decode_str_inplace(dst, len, NULL);
    }
    return MERR_UNSUPPORTED;
}

static int parse_device_types(struct mender_client_update *u, const char *json, jsmntok_t *tokens, int count) {
    int i;

    for (i = 0; i < count; i++) {
        jsmntok_t *t = &tokens[i];

        if (t->type != JSMN_STRING) {
            LOGE("device_type value has to be a string");
            return -1;
        }

        if (!jsonstrcmp(json, t, u->u.get.device_type)) {
            u->u.get.ur->is_compatible = 1;
        }
    }

    return i;
}

static int parse_source(struct mender_client_update *u, const char *json, jsmntok_t *tokens, int count) {
    int i;
    int ntokens = 0;
    mender_err_t merr;

    for (i = 0; i < count; i++) {
        jsmntok_t *tk = &tokens[ntokens++];
        jsmntok_t *tv = &tokens[ntokens++];

        if (tk->type != JSMN_STRING) {
            LOGE("key is not a string");
            return -1;
        }
        if (!jsonstrcmp(json, tk, "uri")) {
            merr = jsonstrcpy(json, tv, u->u.get.ur->uri, ARRAY_SIZE(u->u.get.ur->uri));
            if (merr) {
                LOGE("can't copy uri: %x", merr);
                return -1;
            }
        }
        else if (!jsonstrcmp(json, tk, "expire")) {
            if (tv->type != JSMN_STRING) {
                LOGE("expire is not a string");
                return -1;
            }

            /*
             * XXX: we ignore this on purpose so we don't have to do datetime parsing.
             *      Also, the last time I've checked the GO-client didn't use it either.
             *      Also, we can just rely on the server to return an error when we're
             *      using an expired URL.
             */
        }

        else {
            LOGW("unexpected key");
            ntokens += json_value_nchildtokens(tv);
        }
    }

    return ntokens;
}

static int parse_artifact(struct mender_client_update *u, const char *json, jsmntok_t *tokens, int count) {
    int i;
    int ntokens = 0;
    int rc;
    mender_err_t merr;

    for (i = 0; i < count; i++) {
        jsmntok_t *tk = &tokens[ntokens++];
        jsmntok_t *tv = &tokens[ntokens++];

        if (tk->type != JSMN_STRING) {
            LOGE("key is not a string");
            return -1;
        }
        if (!jsonstrcmp(json, tk, "artifact_name")) {
            merr = jsonstrcpy(json, tv, u->u.get.ur->artifact_name, ARRAY_SIZE(u->u.get.ur->artifact_name));
            if (merr) {
                LOGE("can't copy artifact_name: %x %s", merr, json);
                return -1;
            }
        }
        else if (!jsonstrcmp(json, tk, "source")) {
            if (tv->type != JSMN_OBJECT) {
                LOGE("source has to be an object");
                return -1;
            }

            rc = parse_source(u, json, tv + 1, tv->size);
            if (rc < 0) {
                return -1;
            }
            ntokens += rc;
        }
        else if (!jsonstrcmp(json, tk, "device_types_compatible")) {
            if (tv->type != JSMN_ARRAY) {
                LOGE("device_types_compatible has to be an array");
                return -1;
            }

            rc = parse_device_types(u, json, tv + 1, tv->size);
            if (rc < 0) {
                return -1;
            }
            ntokens += rc;
        }

        else {
            LOGW("unexpected key");
            ntokens += json_value_nchildtokens(tv);
        }
    }

    return ntokens;
}

static int parse_root(struct mender_client_update *u, const char *json, jsmntok_t *tokens, int count) {
    int ntokens = 0;
    int i;
    int rc;

    for (i = 0; i < count; i++) {
        jsmntok_t *tk = &tokens[ntokens++];
        jsmntok_t *tv = &tokens[ntokens++];

        if (tk->type != JSMN_STRING) {
            LOGE("key is not a string: %d", tk->type);
            return -1;
        }

        if (!jsonstrcmp(json, tk, "id")) {
            int len = jsonstrlen(tv);
            if (len != 36) {
                LOGE("invalid ID");
                return -1;
            }
            jsonstrcpy(json, tv, u->u.get.ur->id, ARRAY_SIZE(u->u.get.ur->id));
        }
        else if (!jsonstrcmp(json, tk, "artifact")) {
            if (tv->type != JSMN_OBJECT) {
                LOGE("artifact has to be an object");
                return -1;
            }

            rc = parse_artifact(u, json, tv + 1, tv->size);
            if (rc < 0) {
                return -1;
            }
            ntokens += rc;
        }
        else {
            LOGW("unexpected key");
            ntokens += json_value_nchildtokens(tv);
        }
    }

    return ntokens;
}

void mender_client_update_reset(struct mender_client_update *u) {
    u->url = NULL;
    u->url_len = 0;
    memset(&u->u, 0, sizeof(u->u));

    mender_client_req_ctx_reset(&u->req_ctx);
}

void mender_client_update_data_sent(void *ctx, struct mender_http_client *c) {
    struct mender_client_update *u = ctx;
    mender_err_t err;

    do {
        switch (u->req_ctx.state) {
        case MENDER_CLIENT_REQ_STATE_CONNECT:
            if (u->url) {
                mender_httpbuf_give(c, u->url, u->url_len);
                u->url = NULL;
                u->url_len = 0;
            }
            break;

        default:
            break;
        }

        err = mender_client_req_handle_send(&u->req_ctx);
    } while (err == MERR_TRY_AGAIN);

    if (err) {
        mender_http_client_close(c);
    }
}

static void hdr_ended(void *ctx __unused, struct mender_http_client *c) {
    switch (c->parser.status_code) {
    case HTTP_STATUS_OK:
        /* keep going */
        break;
    default:
        /* unexpected */
        mender_http_client_close(c);
        break;
    }
}

static void closed(void *ctx, struct mender_http_client *c,
    enum mender_http_close_reason reason)
{
    int rc;
    mender_err_t merr;
    mender_err_t cbret;
    struct mender_client_update *u = ctx;
    char *json = NULL;
    size_t json_len;
    jsmn_parser p;
    size_t maxtokens;
    struct mender_alignedstack_ctx tokens_ctx;
    jsmntok_t *tokens = NULL;
    int ntokens = 0;

    if (u->req_ctx.state == MENDER_CLIENT_REQ_STATE_WAIT_FOR_RESPONSE && reason == MENDER_HTTP_CR_CLOSED) {
        if (c->parser.status_code == HTTP_STATUS_UNAUTHORIZED) {
            LOGW("Client not authorized to get update schedule.");
            cbret = MERR_CLIENT_UNAUTHORIZED;
        }
        else if(c->parser.status_code == HTTP_STATUS_OK) {
            LOGD("Have update available");
            cbret = MERR_NONE;
        }
        else if(c->parser.status_code == HTTP_STATUS_NO_CONTENT) {
            LOGD("No update available");
            cbret = MERR_NOT_FOUND;
        }
        else {
            LOGW("Client recieved invalid response status code: %d", reason);
            cbret = MERR_INVALID_HTTP_STATUS;
        }
    }
    else if(u->req_ctx.state == MENDER_CLIENT_REQ_STATE_CONNECT && reason == MENDER_HTTP_CR_INTERNAL_ERROR) {
        cbret = c->internal_error;
    }
    else {
        cbret = MERR_INVALID_STATE;
    }

    /* we got a 200 but no content */
    if (!cbret && mender_httpbuf_num_used(c) == 0) {
        LOGW("200 without body");
        cbret = MERR_NOT_FOUND;
    }

    /* nothing to parse */
    if (cbret) {
        goto do_callback;
    }

    json = mender_httpbuf_base(c);
    json_len = mender_httpbuf_num_used(c);

    jsmn_init(&p);

    maxtokens = mender_alignedstack_num_free(c->stack, 4)/sizeof(jsmntok_t);
    tokens = mender_alignedstack_take(&tokens_ctx, c->stack, maxtokens * sizeof(jsmntok_t), 4);
    if (!tokens) {
        LOGD("not enough stack space for json tokens");
        cbret = MERR_OUT_OF_RESOURCES;
        goto do_callback;
    }

    rc = jsmn_parse(&p, json, json_len, tokens, maxtokens);
    if (rc < 0) {
        LOGE("failed to parse JSON: %d", rc);
        cbret = MERR_INVALID_DATA;
        goto do_callback;
    }
    ntokens = rc;

    if (ntokens < 1 || tokens[0].type != JSMN_OBJECT) {
        LOGE("object expected");
        cbret = MERR_INVALID_DATA;
        goto do_callback;
    }

    rc = parse_root(u, json, &tokens[1], tokens[0].size);
    if (rc < 0) {
        cbret = MERR_INVALID_DATA;
        goto do_callback;
    }

    if (rc < ntokens - 1) {
        LOGW("didn't consume all tokens, %d are left" , ntokens - 1 - rc);
    }

    if (!u->u.get.ur->artifact_name[0]) {
        LOGE("artifact_name not found");
        cbret = MERR_INVALID_DATA;
        goto do_callback;
    }

    if (!u->u.get.ur->id[0]) {
        LOGE("id not found");
        cbret = MERR_INVALID_DATA;
        goto do_callback;
    }

    if (!u->u.get.ur->is_compatible) {
        LOGE("update is not compatible");
        cbret = MERR_UPDATE_INCOMPATIBLE;
        goto do_callback;
    }

    if (!u->u.get.ur->uri[0]) {
        LOGE("uri not found");
        cbret = MERR_INVALID_DATA;
        goto do_callback;
    }

    cbret = MERR_NONE;

do_callback:
    if (tokens) {
        mender_alignedstack_give(&tokens_ctx, c->stack);
    }

    if (json) {
        mender_httpbuf_give(c, json, json_len);
    }

    merr = mender_http_client_end(c);
    if (merr) {
        LOGE("can't end http client: %x", merr);
    }

    if (u->u.get.cb) {
        mender_client_update_get_cb_t cb = u->u.get.cb;
        void *cbctx = u->u.get.cbctx;

        /* from this point on, new requests can be made */
        mender_client_update_reset(u);

        cb(cbctx, cbret);
    }
    else {
        mender_client_update_reset(u);
    }
}

static struct mender_http_callback u_http_cb = {
    .data_sent = mender_client_update_data_sent,
    .hdr_ended = hdr_ended,
    .body_received_chunk = mender_http_client_body_received_chunk_default,
    .body_ended = mender_http_client_body_ended_default,
    .closed = closed,
};

mender_err_t mender_client_update_get(struct mender_client_update *u, const char *server,
        const char *artifact_name, const char *device_type, struct mender_update_response *ur,
        mender_client_update_get_cb_t cb, void *cbctx)
{
    mender_err_t err;
    struct mender_http_client *client = u->req_ctx.client;
    char *url;
    size_t url_len;

    memset(ur, 0, sizeof(*ur));

    if (u->req_ctx.state != MENDER_CLIENT_REQ_STATE_READY) {
        LOGE("another update check is already running");
        return MERR_BUSY;
    }

    if (!artifact_name)
        artifact_name = "";
    if (!device_type)
        device_type = "";

    url = mender_httpbuf_current(client);
    err = mender_client_build_api_url_getfmt(url, mender_httpbuf_num_free(client), &url_len,
        server, "/deployments/device/deployments/next?device_type=%s&artifact_name=%s",
        device_type, artifact_name);
    if (err) {
        return err;
    }
    if (mender_httpbuf_take(client, url_len) != url) {
        return MERR_OUT_OF_RESOURCES;
    }

    u->req_ctx.state = MENDER_CLIENT_REQ_STATE_CONNECT;

    u->url = url;
    u->url_len = url_len;
    u->u.get.cb = cb;
    u->u.get.cbctx = cbctx;
    u->u.get.ur = ur;
    u->u.get.device_type = device_type;

    /* open connection */
    err = mender_http_client_begin(client, MENDER_HTTP_METHOD_GET, u->url, &u_http_cb, u);
    if (err) {
        mender_httpbuf_give(client, u->url, u->url_len);
        mender_client_update_reset(u);
        return err;
    }

    return MERR_NONE;
}

void mender_client_update_create(struct mender_client_update *u, struct mender_http_client *client,
        struct mender_authmgr *authmgr)
{
    memset(u, 0, sizeof(*u));
    mender_client_req_ctx_init(&u->req_ctx, client, authmgr);
}
