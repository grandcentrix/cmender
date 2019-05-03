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

#ifndef MENDER_CLIENT_UPDATE_H
#define MENDER_CLIENT_UPDATE_H

#include <mender/authmgr.h>
#include <mender/http.h>
#include <mender/client.h>
#include <mender/platform/config.h>
#include <jsmn.h>

typedef void (*mender_client_update_get_cb_t)(void *ctx, mender_err_t err);

struct mender_client_update_fetch_cb {
    mender_err_t (*on_init_success)(void *ctx);
    void (*on_finish)(void *ctx, mender_err_t err);
    mender_err_t (*on_data)(void *ctx, const void *data, size_t len);
};

struct mender_client_update {
    struct mender_client_req_ctx req_ctx;
    char *url;
    size_t url_len;

    union {
        struct {
            mender_client_update_get_cb_t cb;
            struct mender_update_response *ur;
            void *cbctx;
            const char *device_type;
        } get;

        struct {
            struct mender_client_update_fetch_cb *cb;
            void *cbctx;
        } fetch;
    } u;
};

void mender_client_update_create(struct mender_client_update *u, struct mender_http_client *client,
        struct mender_authmgr *authmgr);
mender_err_t mender_client_update_get(struct mender_client_update *u, const char *server,
        const char *artifact_name, const char *device_type, struct mender_update_response *ur,
        mender_client_update_get_cb_t cb, void *cbctx);
mender_err_t mender_client_update_fetch(struct mender_client_update *u, const char *url,
        mender_duration_t max_wait,
        struct mender_client_update_fetch_cb *cb, void *cbctx);

void mender_client_update_reset(struct mender_client_update *u);
void mender_client_update_data_sent(void *ctx, struct mender_http_client *c);

#endif /* MENDER_CLIENT_INVENTORY_H */
