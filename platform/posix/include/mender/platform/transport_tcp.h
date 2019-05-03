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

#ifndef MENDER_PLATFORM_TRANSPORT_TCP_H
#define MENDER_PLATFORM_TRANSPORT_TCP_H

#include <mender/transport.h>
#include <mender/platform/eventloop.h>
#include <mender/platform/http_transport_common.h>

enum mender_http_transport_tcp_state {
    MENDER_HTTP_TRANSPORT_TCP_STATE_READY,
    MENDER_HTTP_TRANSPORT_TCP_STATE_INITIALIZED,
    MENDER_HTTP_TRANSPORT_TCP_STATE_CONNECT,
    MENDER_HTTP_TRANSPORT_TCP_STATE_CONNECTED,
};

struct mender_http_transport_tcp {
    struct mender_http_transport t;
    struct eventloop_slot_fd eventloop_slot;
    struct mender_platform_eventloop *el;

    struct eventloop_slot_loop eventloop_cb;
    mender_time_t cb_next;

    enum mender_http_transport_tcp_state state;

    struct mender_http_transport_connect_ctx connect_ctx;

    const void *write_buf;
    size_t write_len;
};

void mender_http_transport_tcp_create(struct mender_http_transport_tcp *tcp, struct mender_platform_eventloop *el);

#endif /* MENDER_PLATFORM_TRANSPORT_TCP_H */
