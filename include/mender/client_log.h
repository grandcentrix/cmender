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

#ifndef MENDER_CLIENT_LOG_H
#define MENDER_CLIENT_LOG_H

#include <mender/authmgr.h>
#include <mender/http.h>
#include <mender/client.h>

typedef void (*mender_client_log_cb_t)(void *ctx, mender_err_t err);

struct mender_client_log {
    mender_client_log_cb_t cb;
    void *cbctx;

    struct mender_client_req_ctx req_ctx;
    char *url;
    const char *logs;
    size_t url_len;
};

void mender_client_log_create(struct mender_client_log *l, struct mender_http_client *client,
        struct mender_authmgr *authmgr);
mender_err_t mender_client_log_upload(struct mender_client_log *l, const char *server,
        const char *deployment_id, const char *logs,
        mender_client_log_cb_t cb, void *cbctx);

#endif /* MENDER_CLIENT_LOG_H */
