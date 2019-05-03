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

#ifndef MENDER_TRANSPORT_H
#define MENDER_TRANSPORT_H

#include <mender/error.h>
#include <mender/platform/types.h>

struct mender_http_transport_cb {
    void (*on_connected)(void *ctx);
    void (*data_available)(void *ctx);
    void (*data_sent)(void *ctx);
    void (*on_error)(void *ctx, mender_err_t err);
};

struct mender_http_transport {
    struct mender_http_transport_cb *cb;
    void *cb_ctx;

    void (*set_read_cb_enabled)(struct mender_http_transport *t, int enabled);
    void (*connect)(struct mender_http_transport *t, const char *host, int port, int timeout_ms);
    mender_err_t (*read)(struct mender_http_transport *t, void *buf, size_t len, size_t *pactual);
    void (*write)(struct mender_http_transport *t, const void *buf, size_t len);
    mender_err_t (*close)(struct mender_http_transport *t);
};

#endif /* MENDER_TRANSPORT_H */
