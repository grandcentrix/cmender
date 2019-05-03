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

#ifndef MENDER_PLATFORM_HTTP_TRANSPORT_COMMON_H
#define MENDER_PLATFORM_HTTP_TRANSPORT_COMMON_H

#include <mender/error.h>
#include <sys/time.h>

struct mender_http_transport_connect_ctx {
    struct timeval tv;
    struct addrinfo *addr_list;
    struct addrinfo *cur;
    int *pfd;
};

mender_err_t mender_http_transport_util_connect(struct mender_http_transport_connect_ctx *ctx,
    const char *host, int port, int *pfd, int timeout_ms);
mender_err_t mender_http_transport_util_connect_cont(struct mender_http_transport_connect_ctx *ctx);
void mender_http_transport_util_connect_cleanup(struct mender_http_transport_connect_ctx *ctx);

#endif /* MENDER_PLATFORM_HTTP_TRANSPORT_COMMON_H */
