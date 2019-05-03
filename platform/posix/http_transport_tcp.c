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
#include <mender/internal/compiler.h>
#include <mender/platform/transport_tcp.h>
#include <mender/platform/eventloop.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define to_tcp(s) containerof((s), struct mender_http_transport_tcp, t)

static void tcp_fail(struct mender_http_transport_tcp *tcp, mender_err_t err) {
    if (tcp->state != MENDER_HTTP_TRANSPORT_TCP_STATE_READY) {
        tcp->t.close(&tcp->t);
    }
    if (tcp->t.cb && tcp->t.cb->on_error) {
        tcp->t.cb->on_error(tcp->t.cb_ctx, err);
    }
}

static void data_cb(void *ctx, int fd __unused, enum eventloop_flags flags) {
    struct mender_http_transport_tcp *tcp = ctx;
    mender_err_t err;

    if (flags & EVENTLOOP_FLAG_EXCEPT) {
        LOGE("EVENTLOOP_FLAG_EXCEPT, closing the connection");
        tcp_fail(tcp, MERR_UNKNOWN);
        return;
    }

    switch (tcp->state) {
    case MENDER_HTTP_TRANSPORT_TCP_STATE_CONNECT:
        /* we're connected now */
        if (flags & EVENTLOOP_FLAG_WRITE) {
            int rc;
            int result = -1;
            socklen_t result_len = sizeof(result);

            rc = getsockopt(tcp->eventloop_slot.fd, SOL_SOCKET, SO_ERROR, &result, &result_len);
            if (rc < 0) {
                LOGE("getsockopt failed: %d", rc);
                tcp_fail(tcp, MERR_UNKNOWN);
                return;
            }

            if (result) {
                LOGE("connect failed: %d", result);

                /* the connection failed, try the next addrinfo entry */
                err = mender_http_transport_util_connect_cont(&tcp->connect_ctx);
                if (err) {
                    LOGE("mender_http_transport_util_connect_cont failed");
                    mender_http_transport_util_connect_cleanup(&tcp->connect_ctx);
                    tcp_fail(tcp, err);
                }
                return;
            }

            mender_http_transport_util_connect_cleanup(&tcp->connect_ctx);

            tcp->state = MENDER_HTTP_TRANSPORT_TCP_STATE_CONNECTED;
            tcp->eventloop_slot.flags &= ~EVENTLOOP_FLAG_WRITE;
            if (tcp->t.cb && tcp->t.cb->on_connected) {
                tcp->t.cb->on_connected(tcp->t.cb_ctx);
            }
            break;
        }
        break;

    case MENDER_HTTP_TRANSPORT_TCP_STATE_CONNECTED:
        if (flags & EVENTLOOP_FLAG_READ) {
            if (tcp->t.cb) {
               tcp->t.cb->data_available(tcp->t.cb_ctx);
            }
        }

        if (flags & EVENTLOOP_FLAG_WRITE) {
            if (tcp->write_buf && tcp->write_len) {
                const void *buf = tcp->write_buf;
                size_t len = tcp->write_len;

                buf = NULL;
                len = 0;

                tcp->t.write(&tcp->t, buf, len);
            }
        }
        break;

    default:
        LOGE("invalid state %d, closing the connection", tcp->state);

        tcp_fail(tcp, MERR_INVALID_STATE);
        break;
    }
}

static void transport_set_read_cb_enabled(struct mender_http_transport *t, int enabled) {
    struct mender_http_transport_tcp *tcp = to_tcp(t);

    if (enabled) {
        tcp->eventloop_slot.flags |= EVENTLOOP_FLAG_READ;
    }
    else {
        tcp->eventloop_slot.flags &= ~EVENTLOOP_FLAG_READ;
    }
}

static void transport_connect(struct mender_http_transport *t, const char *host, int port, int timeout_ms) {
    struct mender_http_transport_tcp *tcp = to_tcp(t);
    mender_err_t merr;

    if (tcp->state != MENDER_HTTP_TRANSPORT_TCP_STATE_READY) {
        LOGE("transport is already in use");
        tcp_fail(tcp, MERR_BUSY);
        return;
    }

    mender_eventloop_register_fd(tcp->el, &tcp->eventloop_slot);
    tcp->state = MENDER_HTTP_TRANSPORT_TCP_STATE_INITIALIZED;
    tcp->eventloop_slot.flags = EVENTLOOP_FLAG_EXCEPT;

    /* connect to server */
    tcp->state = MENDER_HTTP_TRANSPORT_TCP_STATE_CONNECT;
    tcp->eventloop_slot.flags |= EVENTLOOP_FLAG_WRITE;
    merr = mender_http_transport_util_connect(&tcp->connect_ctx, host, port, &tcp->eventloop_slot.fd, timeout_ms);
    if (merr) {
        LOGE("mender_http_transport_util_connect failed");
        tcp_fail(tcp, MERR_UNKNOWN);
        return;
    }
}

static mender_err_t transport_read(struct mender_http_transport *t, void *_buf, size_t len, size_t *pactual) {
    struct mender_http_transport_tcp *tcp = to_tcp(t);
    ssize_t nbytes;
    size_t total = 0;
    uint8_t *buf = (uint8_t *)_buf;

    while (len) {
        /* clip to SSIZE_MAX per read */
        size_t toread = len;
        if (toread > SSIZE_MAX)
            toread = SSIZE_MAX;

        nbytes = read(tcp->eventloop_slot.fd, buf, toread);
        if (nbytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return MERR_TRY_AGAIN;

            return MERR_UNKNOWN;
        }

        /* connection got closed */
        if (nbytes == 0) {
            /* report previously read bytes first */
            if (total) {
                break;
            }

            *pactual = 0;
            return MERR_NONE;
        }

        total += nbytes;
        len -= nbytes;
        buf += nbytes;

        /* if we got a short-read stop here */
        if (nbytes < (ssize_t)toread)
            break;
    }

    *pactual = total;
    return MERR_NONE;
}

static void queue_retry(struct mender_http_transport_tcp *tcp, const void *buf, size_t len) {
    tcp->write_buf = buf;
    tcp->write_len = len;
    tcp->eventloop_slot.flags |= EVENTLOOP_FLAG_WRITE;
}

static void transport_write(struct mender_http_transport *t, const void *buf, size_t len) {
    struct mender_http_transport_tcp *tcp = to_tcp(t);
    ssize_t nbytes;
    size_t towrite = MIN(len, SSIZE_MAX);

    if (tcp->state != MENDER_HTTP_TRANSPORT_TCP_STATE_CONNECTED) {
        LOGE("transport is not connected");
        tcp_fail(tcp, MERR_UNKNOWN);
        return;
    }

    if (tcp->write_buf || tcp->write_len) {
        LOGE("another write is still in progress");
        tcp_fail(tcp, MERR_BUSY);
        return;
    }

    tcp->eventloop_slot.flags &= ~EVENTLOOP_FLAG_WRITE;

    nbytes = write(tcp->eventloop_slot.fd, buf, towrite);
    if (nbytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            queue_retry(tcp, buf, len);
            return;
        }

        LOGE("write failed: rc=%zd errno=%d", nbytes, errno);
        tcp_fail(tcp, MERR_UNKNOWN);
        return;
    }
    if ((size_t)nbytes < len) {
        queue_retry(tcp, buf + nbytes, len - nbytes);
        return;
    }

    // run the callback via the eventloop so we don't recursively call transport_write
    tcp->cb_next = 0;
}

static mender_err_t transport_close(struct mender_http_transport *t) {
    struct mender_http_transport_tcp *tcp = to_tcp(t);
    int rc;

    if (tcp->state != MENDER_HTTP_TRANSPORT_TCP_STATE_READY) {
        tcp->eventloop_slot.flags = 0;
        mender_eventloop_remove_fd(tcp->el, &tcp->eventloop_slot);

        rc = close(tcp->eventloop_slot.fd);
        tcp->eventloop_slot.fd = -1;
        tcp->state = MENDER_HTTP_TRANSPORT_TCP_STATE_READY;

        if (rc)
            return MERR_UNKNOWN;
    }

    return MERR_NONE;
}

static void event_cb(void *ctx) {
    struct mender_http_transport_tcp *tcp = ctx;

    if (tcp->cb_next != MENDER_TIME_INFINITE) {
        tcp->cb_next = MENDER_TIME_INFINITE;
        if (tcp->t.cb && tcp->t.cb->data_sent) {
            tcp->t.cb->data_sent(tcp->t.cb_ctx);
        }
    }
}

static void event_cb_get_timeout(void *ctx, mender_time_t *tnext) {
    struct mender_http_transport_tcp *tcp = ctx;
    *tnext = tcp->cb_next;
}

void mender_http_transport_tcp_create(struct mender_http_transport_tcp *tcp, struct mender_platform_eventloop *el) {
    memset(tcp, 0, sizeof(*tcp));
    tcp->el = el;
    tcp->state = MENDER_HTTP_TRANSPORT_TCP_STATE_READY;
    tcp->t.set_read_cb_enabled = transport_set_read_cb_enabled;
    tcp->t.connect = transport_connect;
    tcp->t.read = transport_read;
    tcp->t.write = transport_write;
    tcp->t.close = transport_close;

    tcp->eventloop_slot.ctx = tcp;
    tcp->eventloop_slot.fd = -1;
    tcp->eventloop_slot.flags = 0;
    tcp->eventloop_slot.cb = data_cb;

    tcp->cb_next = MENDER_TIME_INFINITE;
    tcp->eventloop_cb.ctx = tcp;
    tcp->eventloop_cb.cb = event_cb;
    tcp->eventloop_cb.get_timeout = event_cb_get_timeout;
    mender_eventloop_register_loop_cb(tcp->el, &tcp->eventloop_cb);
}
