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

#ifndef MENDER_CLIENT_H
#define MENDER_CLIENT_H

#include <mender/time.h>
#include <mender/error.h>
#include <mender/authmgr.h>
#include <mender/http.h>

enum mender_deployment_status {
    MENDER_DEPLOYMENT_STATUS_INVALID = 0,
    MENDER_DEPLOYMENT_STATUS_INSTALLING,
    MENDER_DEPLOYMENT_STATUS_DOWNLOADING,
    MENDER_DEPLOYMENT_STATUS_REBOOTING,
    MENDER_DEPLOYMENT_STATUS_SUCCESS,
    MENDER_DEPLOYMENT_STATUS_FAILURE,
    MENDER_DEPLOYMENT_STATUS_ALREADY_INSTALLED
};

struct mender_update_response {
    char uri[4096];
    int is_compatible;
    char artifact_name[32];
    char id[37];
};

enum mender_client_req_state {
    MENDER_CLIENT_REQ_STATE_READY,
    MENDER_CLIENT_REQ_STATE_CONNECT,
    MENDER_CLIENT_REQ_STATE_SEND_CONTENT_TYPE,
    MENDER_CLIENT_REQ_STATE_SEND_CONTENT_LENGTH,

    MENDER_CLIENT_REQ_STATE_SEND_BEARER_KEY,
    MENDER_CLIENT_REQ_STATE_SEND_BEARER_VALUE,
    MENDER_CLIENT_REQ_STATE_SEND_BEARER_END,

    MENDER_CLIENT_REQ_STATE_SEND_HDR_END,
    MENDER_CLIENT_REQ_STATE_SEND_DATA,
    MENDER_CLIENT_REQ_STATE_WAIT_FOR_RESPONSE,
};

struct mender_client_req_ctx {
    enum mender_client_req_state state;
    struct mender_http_client *client;
    struct mender_authmgr *authmgr;

    void *token;
    size_t token_len;
    const void *data;
    size_t data_len;
};

void mender_client_req_ctx_init(struct mender_client_req_ctx *ctx,
    struct mender_http_client *client, struct mender_authmgr *authmgr);
void mender_client_req_ctx_reset(struct mender_client_req_ctx *ctx);
mender_err_t mender_client_req_handle_send(struct mender_client_req_ctx *ctx);

mender_err_t mender_client_build_api_url(char *buf, size_t maxsz,  size_t *pactual,
        const char *server, const char *url);
mender_err_t mender_client_build_api_url_getfmt(char *buf, size_t maxsz,  size_t *pactual,
        const char *server, const char *fmt, ...);
mender_err_t mender_client_get_exponential_backoff_time(int tried,
        mender_duration_t max_interval, mender_duration_t *pduration);
const char * mender_deployment_status_to_str(enum mender_deployment_status status);

#endif /* MENDER_CLIENT_H */
