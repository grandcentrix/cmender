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
#include <mender/platform/log.h>
#include <mender/platform/http_transport_common.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

mender_err_t mender_http_transport_util_connect(struct mender_http_transport_connect_ctx *ctx,
    const char *host, int port, int *pfd, int timeout_ms)
{
    int rc;
    struct addrinfo hints;
    char sport[6];

    /* ports can't be bigger than this, return early  */
    if (port > UINT16_MAX) {
        LOGE("invalid port: %u", port);
        return MERR_INVALID_ARGUMENTS;
    }

    /* convert the port to a string */
    rc = snprintf(sport, sizeof(sport), "%u", port);
    if (rc < 0 || rc >= (int)sizeof(sport)) {
        LOGE("BUG: can't convert port to string");
        return MERR_IMPLEMENTATION_BUG;
    }

    /* convert the time to the format we need */
    memset(&ctx->tv, 0, sizeof(ctx->tv));
    ctx->tv.tv_sec = timeout_ms / 1000;
    ctx->tv.tv_usec = (timeout_ms - (ctx->tv.tv_sec * 1000)) * 1000;

    /* Do name resolution with both IPv6 and IPv4 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    rc = getaddrinfo(host, sport, &hints, &ctx->addr_list);
    if (rc != 0) {
        LOGE("getaddrinfo(%s, %s): %d", host, sport, rc);
        return MERR_UNKNOWN;
    }

    ctx->cur = ctx->addr_list;
    ctx->pfd = pfd;
    *(ctx->pfd) = -1;
    return mender_http_transport_util_connect_cont(ctx);
}

mender_err_t mender_http_transport_util_connect_cont(struct mender_http_transport_connect_ctx *ctx) {
    int rc;
    int fd;
    mender_err_t ret;

    /* Try the sockaddrs until a connection succeeds */
    ret = MERR_UNKNOWN;
    for (; ctx->cur != NULL; ctx->cur = ctx->cur->ai_next) {
        if (*(ctx->pfd) >= 0) {
            close(*(ctx->pfd));
            *(ctx->pfd) = -1;
        }

        fd = socket(ctx->cur->ai_family, ctx->cur->ai_socktype, ctx->cur->ai_protocol);
        if (fd < 0) {
            LOGD("can't open socket: rc=%d errno=%d", fd, errno);
            continue;
        }

        /* set timeout */
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &ctx->tv, sizeof(ctx->tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &ctx->tv, sizeof(ctx->tv));

        /* get current flags */
        rc = fcntl(fd, F_GETFL, 0);
        if (rc < 0) {
            LOGE("GETFL error: %d: %s", rc, strerror(errno));
            close(fd);
            ret = MERR_UNKNOWN;
            break;
        }

        /* enable non-blocking mode */
        rc = fcntl(fd, F_SETFL, rc | O_NONBLOCK);
        if (rc) {
            LOGE("can't enable O_NONBLOCK: %d: %s", rc, strerror(errno));
            close(fd);
            ret = MERR_UNKNOWN;
            break;
        }

        rc = connect(fd, ctx->cur->ai_addr, ctx->cur->ai_addrlen);
        if (rc == 0 || (rc && errno==EINPROGRESS)) {
            *(ctx->pfd) = fd;
            ret = MERR_NONE;
            ctx->cur = ctx->cur->ai_next;
            break;
        }

        close(fd);
    }

    return ret;
}

void mender_http_transport_util_connect_cleanup(struct mender_http_transport_connect_ctx *ctx) {
    if (ctx->addr_list) {
        freeaddrinfo(ctx->addr_list);
        ctx->addr_list = NULL;
    }
}
