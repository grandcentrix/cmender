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

#ifndef MENDER_CLIENT_AUTH_H
#define MENDER_CLIENT_AUTH_H

#include <mender/authmgr.h>
#include <mender/http.h>

typedef void (*mender_client_auth_cb_t)(void *ctx, mender_err_t err, void *buf, size_t len);

enum mender_client_auth_state {
    MENDER_CLIENT_AUTH_STATE_READY,
    MENDER_CLIENT_AUTH_STATE_CONNECT,
    MENDER_CLIENT_AUTH_STATE_SEND_CONTENT_TYPE,
    MENDER_CLIENT_AUTH_STATE_SEND_CONTENT_LENGTH,

    MENDER_CLIENT_AUTH_STATE_SEND_BEARER_KEY,
    MENDER_CLIENT_AUTH_STATE_SEND_BEARER_VALUE,
    MENDER_CLIENT_AUTH_STATE_SEND_BEARER_END,

    MENDER_CLIENT_AUTH_STATE_SEND_SIG_KEY,
    MENDER_CLIENT_AUTH_STATE_SEND_SIG_VALUE,
    MENDER_CLIENT_AUTH_STATE_SEND_SIG_END,

    MENDER_CLIENT_AUTH_STATE_SEND_HDR_END,
    MENDER_CLIENT_AUTH_STATE_SEND_DATA,
    MENDER_CLIENT_AUTH_STATE_WAIT_FOR_RESPONSE,
    MENDER_CLIENT_AUTH_STATE_IN_CALLBACK,
};

struct mender_client_auth {
    struct mender_http_client *client;
    struct mender_authmgr *authmgr;

    enum mender_client_auth_state state;
    mender_client_auth_cb_t cb;
    void *cbctx;

    char *url;
    size_t url_len;
    void *authdata;
    size_t authdata_len;
    const char *data;
    size_t data_len;
    const char *sig;
    size_t sig_len;
    const char *token;
    size_t token_len;
};

void mender_client_auth_create(struct mender_client_auth *ca, struct mender_http_client *client,
        struct mender_authmgr *authmgr);
mender_err_t mender_client_auth_request(struct mender_client_auth *ca, const char *server,
        mender_client_auth_cb_t cb, void *cbctx);
void mender_client_auth_finish_request(struct mender_client_auth *ca);

#endif /* MENDER_CLIENT_AUTH_H */
