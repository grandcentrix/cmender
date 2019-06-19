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
#include <mender/platform/transport_ssl.h>
#include <mender/platform/eventloop.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "lwip_fixup.h"

static const char *ssl_client_pers = "mender_ssl_client";

#define to_ssl(s) containerof((s), struct mender_http_transport_ssl, t)

static void ssl_fail(struct mender_http_transport_ssl *ssl, mender_err_t err) {
    if (ssl->state != MENDER_HTTP_TRANSPORT_SSL_STATE_READY) {
        ssl->t.close(&ssl->t);
    }
    if (ssl->t.cb && ssl->t.cb->on_error) {
        ssl->t.cb->on_error(ssl->t.cb_ctx, err);
    }
}

static void ssl_handshake_retry(struct mender_http_transport_ssl *ssl) {
    int rc;
    int flags;

    ssl->eventloop_slot.flags &= ~EVENTLOOP_FLAG_READ;
    ssl->eventloop_slot.flags &= ~EVENTLOOP_FLAG_WRITE;

    rc = mbedtls_ssl_handshake(&ssl->ctx);
    if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
        ssl->eventloop_slot.flags |= EVENTLOOP_FLAG_READ;
        return;
    }
    if (rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        ssl->eventloop_slot.flags |= EVENTLOOP_FLAG_WRITE;
        return;
    }

    if (rc) {
        LOGE("mbedtls_ssl_handshake returned -0x%x", -rc);
        ssl_fail(ssl, MERR_SSL_HANDSHAKE_ERROR);
        return;
    }

    /* verify the server certificate */
    flags = mbedtls_ssl_get_verify_result(&ssl->ctx);
    if (flags != 0) {
        LOGE("mbedtls_ssl_get_verify_result returned %d", flags);
        ssl_fail(ssl, MERR_SSL_CERTIFICATE_ERROR);
        return;
    }

    ssl->state = MENDER_HTTP_TRANSPORT_SSL_STATE_CONNECTED;
    if (ssl->t.cb && ssl->t.cb->on_connected) {
        ssl->t.cb->on_connected(ssl->t.cb_ctx);
    }
}

static void ssl_handshake_start(struct mender_http_transport_ssl *ssl) {
    int rc;

    ssl->netctx.fd = ssl->eventloop_slot.fd;

    /* ssl config */
    rc = mbedtls_ssl_config_defaults(&ssl->conf, MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        LOGE("mbedtls_ssl_config_defaults returned %d", rc);
        goto out_close;
    }

#ifdef CONFIG_MENDER_PLATFORM_SSL_FRAG_LEN
#define _CONCAT(x,y) x ## y
#define CONCAT(x,y) _CONCAT(x,y)
#define LOCAL_FRAGMENT_LENGTH CONCAT(MBEDTLS_SSL_MAX_FRAG_LEN_, CONFIG_MENDER_PLATFORM_SSL_FRAG_LEN)
    mbedtls_ssl_conf_max_frag_len(&ssl->conf, LOCAL_FRAGMENT_LENGTH);
#undef LOCAL_FRAGMENT_LENGTH
#endif

    if (ssl->ciphersuites) {
        mbedtls_ssl_conf_ciphersuites(&ssl->conf, ssl->ciphersuites);
    }

    if (ssl->der_buf) {
        mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&ssl->conf, &ssl->cacert, NULL);
    }
    else {
        mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_NONE);
    }

    mbedtls_ssl_conf_rng(&ssl->conf, mbedtls_ctr_drbg_random, &ssl->ctr_drbg);

    /* ssl setup */
    rc = mbedtls_ssl_setup(&ssl->ctx, &ssl->conf);
    if (rc != 0) {
        LOGE("mbedtls_ssl_setup returned %d", rc);
        goto out_close;
    }

    /* set hostname */
    rc = mbedtls_ssl_set_hostname(&ssl->ctx, ssl->host);
    if (rc != 0) {
        LOGE("mbedtls_ssl_set_hostname returned %d", rc);
        goto out_close;
    }

    /* we're not allowed to use this from now on */
    ssl->host = NULL;

    /* set IO functions */
    mbedtls_ssl_set_bio(&ssl->ctx, &ssl->netctx, mbedtls_net_send, mbedtls_net_recv, NULL);

    ssl_handshake_retry(ssl);
    return;

out_close:
    ssl_fail(ssl, MERR_UNKNOWN);
}

static void data_cb(void *ctx, int fd __unused, enum eventloop_flags flags) {
    struct mender_http_transport_ssl *ssl = ctx;
    mender_err_t err;

    if (flags & EVENTLOOP_FLAG_EXCEPT) {
        LOGE("EVENTLOOP_FLAG_EXCEPT, closing the connection");
        ssl_fail(ssl, MERR_UNKNOWN);
        return;
    }

    switch (ssl->state) {
    case MENDER_HTTP_TRANSPORT_SSL_STATE_CONNECT:
        /* we're connected now */
        if (flags & EVENTLOOP_FLAG_WRITE) {
            int rc;
            int result = -1;
            socklen_t result_len = sizeof(result);

            rc = getsockopt(ssl->eventloop_slot.fd, SOL_SOCKET, SO_ERROR, &result, &result_len);
            if (rc < 0) {
                LOGE("getsockopt failed: %d", rc);
                ssl_fail(ssl, MERR_UNKNOWN);
                return;
            }

            if (result) {
                LOGE("connect failed: %d", result);

                /* the connection failed, try the next addrinfo entry */
                err = mender_http_transport_util_connect_cont(&ssl->connect_ctx);
                if (err) {
                    LOGE("mender_http_transport_util_connect_cont failed");
                    mender_http_transport_util_connect_cleanup(&ssl->connect_ctx);
                    ssl_fail(ssl, err);
                }
                return;
            }

            mender_http_transport_util_connect_cleanup(&ssl->connect_ctx);
            ssl->state = MENDER_HTTP_TRANSPORT_SSL_STATE_HANDSHAKE;
            ssl->eventloop_slot.flags &= ~EVENTLOOP_FLAG_WRITE;
            ssl_handshake_start(ssl);
            break;
        }
        break;

    case MENDER_HTTP_TRANSPORT_SSL_STATE_HANDSHAKE:
        if (flags & EVENTLOOP_FLAG_READ || flags & EVENTLOOP_FLAG_WRITE) {
            ssl_handshake_retry(ssl);
        }
        break;

    case MENDER_HTTP_TRANSPORT_SSL_STATE_CONNECTED:
        if (flags & EVENTLOOP_FLAG_READ) {
            if (ssl->t.cb) {
                /*
                 * mbedtls has an internal buffer, so read until it's empty,
                 * but at least once so the first one will actually run the read() syscall
                 */
                do {
                    ssl->t.cb->data_available(ssl->t.cb_ctx);
                } while (mbedtls_ssl_get_bytes_avail(&ssl->ctx));
            }
        }

        if (flags & EVENTLOOP_FLAG_WRITE) {
            if (ssl->write_buf && ssl->write_len) {
                const void *buf = ssl->write_buf;
                size_t len = ssl->write_len;

                ssl->write_buf = NULL;
                ssl->write_len = 0;

                ssl->t.write(&ssl->t, buf, len);
            }
        }
        break;

    default:
        LOGE("invalid state %d, closing the connection", ssl->state);

        ssl_fail(ssl, MERR_INVALID_STATE);
        break;
    }
}

static void transport_set_read_cb_enabled(struct mender_http_transport *t, int enabled) {
    struct mender_http_transport_ssl *ssl = to_ssl(t);

    if (enabled) {
        ssl->eventloop_slot.flags |= EVENTLOOP_FLAG_READ;
    }
    else {
        ssl->eventloop_slot.flags &= ~EVENTLOOP_FLAG_READ;
    }
}

static void transport_connect(struct mender_http_transport *t, const char *host, int port, int timeout_ms) {
    struct mender_http_transport_ssl *ssl = to_ssl(t);
    int rc;
    mender_err_t merr;

    if (ssl->state != MENDER_HTTP_TRANSPORT_SSL_STATE_READY) {
        LOGE("transport is already in use");
        ssl_fail(ssl, MERR_BUSY);
        return;
    }

    /* initialize session data */
    mbedtls_net_init(&ssl->netctx);
    mbedtls_ssl_init(&ssl->ctx);
    mbedtls_ssl_config_init(&ssl->conf);
    mbedtls_x509_crt_init(&ssl->cacert);
    mbedtls_ctr_drbg_init(&ssl->ctr_drbg);
    mbedtls_entropy_init(&ssl->entropy);
    mender_eventloop_register_fd(ssl->el, &ssl->eventloop_slot);
    ssl->state = MENDER_HTTP_TRANSPORT_SSL_STATE_INITIALIZED;
    ssl->eventloop_slot.flags = EVENTLOOP_FLAG_EXCEPT;

    /* seed the RNG */
    rc = mbedtls_ctr_drbg_seed(&ssl->ctr_drbg, mbedtls_entropy_func,
            &ssl->entropy, (const unsigned char *)ssl_client_pers, strlen(ssl_client_pers));
    if (rc != 0) {
        LOGE("mbedtls_ctr_drbg_seed returned %d", rc);
        ssl_fail(ssl, MERR_UNKNOWN);
        return;
    }

    /* initialize certificates */
    if (ssl->der_buf) {
        rc = mbedtls_x509_crt_parse(&ssl->cacert,
            (const unsigned char *) ssl->der_buf, ssl->der_sz);
        if (rc != 0) {
            LOGE("mbedtls_x509_crt_parse returned -0x%x", -rc);
            ssl_fail(ssl, MERR_UNKNOWN);
            return;
        }
    }

    /* connect to server */
    ssl->state = MENDER_HTTP_TRANSPORT_SSL_STATE_CONNECT;
    ssl->eventloop_slot.flags |= EVENTLOOP_FLAG_WRITE;
    merr = mender_http_transport_util_connect(&ssl->connect_ctx, host, port, &ssl->eventloop_slot.fd, timeout_ms);
    if (merr) {
        LOGE("mender_http_transport_util_connect failed");
        ssl_fail(ssl, MERR_UNKNOWN);
        return;
    }
}

static mender_err_t transport_read(struct mender_http_transport *t, void *buf, size_t len, size_t *pactual) {
    struct mender_http_transport_ssl *ssl = to_ssl(t);
    int ret;
    size_t bytes_available;

    if (ssl->state != MENDER_HTTP_TRANSPORT_SSL_STATE_CONNECTED) {
        LOGE("transport is not connected");
        return MERR_INVALID_STATE;
    }

    /* this ensures we won't block in data_cb */
    bytes_available = mbedtls_ssl_get_bytes_avail(&ssl->ctx);
    if (bytes_available && len > bytes_available)
        len = bytes_available;

    ret = mbedtls_ssl_read(&ssl->ctx, (unsigned char *)buf, len);
    if (ret < 0) {
        /* the mbedtls buffer is now empty */
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return MERR_TRY_AGAIN;
        }

        /* connection got closed */
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            *pactual = 0;
            return MERR_NONE;
        }

        LOGE("mbedtls_ssl_read error: %d", ret);
        return MERR_UNKNOWN;
    }

    *pactual = (size_t)ret;
    return MERR_NONE;
}

static void queue_retry(struct mender_http_transport_ssl *ssl, const void *buf, size_t len) {
    ssl->write_buf = buf;
    ssl->write_len = len;
    ssl->eventloop_slot.flags |= EVENTLOOP_FLAG_WRITE;
}

static void transport_write(struct mender_http_transport *t, const void *buf, size_t len) {
    struct mender_http_transport_ssl *ssl = to_ssl(t);
    int rc;
    size_t towrite = MIN(len, INT_MAX);

    if (ssl->state != MENDER_HTTP_TRANSPORT_SSL_STATE_CONNECTED) {
        LOGE("transport is not connected");
        ssl_fail(ssl, MERR_INVALID_STATE);
        return;
    }

    if (ssl->write_buf || ssl->write_len) {
        LOGE("another write is still in progress");
        ssl_fail(ssl, MERR_BUSY);
        return;
    }

    ssl->eventloop_slot.flags &= ~EVENTLOOP_FLAG_WRITE;

    rc = mbedtls_ssl_write(&ssl->ctx, buf, towrite);
    if (rc < 0) {
        if (rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            queue_retry(ssl, buf, len);
            return;
        }

        LOGE("mbedtls_ssl_write failed: %d", rc);
        ssl_fail(ssl, MERR_UNKNOWN);
        return;
    }
    if ((size_t)rc < len) {
        queue_retry(ssl, buf + rc, len - rc);
        return;
    }

    // run the callback via the eventloop so we don't recursively call transport_write
    ssl->cb_next = 0;
}

static mender_err_t transport_close(struct mender_http_transport *t) {
    struct mender_http_transport_ssl *ssl = to_ssl(t);

    if (ssl->state != MENDER_HTTP_TRANSPORT_SSL_STATE_READY) {
        ssl->eventloop_slot.flags = 0;
        mender_eventloop_remove_fd(ssl->el, &ssl->eventloop_slot);

        mbedtls_ssl_close_notify(&ssl->ctx);
        mbedtls_net_free(&ssl->netctx);
        mbedtls_x509_crt_free(&ssl->cacert);
        mbedtls_ssl_free(&ssl->ctx);
        mbedtls_ssl_config_free(&ssl->conf);
        mbedtls_ctr_drbg_free(&ssl->ctr_drbg);
        mbedtls_entropy_free(&ssl->entropy);
        ssl->eventloop_slot.fd = -1;
        ssl->state = MENDER_HTTP_TRANSPORT_SSL_STATE_READY;

        ssl->write_buf = NULL;
        ssl->write_len = 0;
    }
    else {
        LOGW("transport was already closed");
    }

    return MERR_NONE;
}

static void event_cb(void *ctx) {
    struct mender_http_transport_ssl *ssl = ctx;

    if (ssl->cb_next != MENDER_TIME_INFINITE) {
        ssl->cb_next = MENDER_TIME_INFINITE;
        if (ssl->t.cb && ssl->t.cb->data_sent) {
            ssl->t.cb->data_sent(ssl->t.cb_ctx);
        }
    }
}

static void event_cb_get_timeout(void *ctx, mender_time_t *tnext) {
    struct mender_http_transport_ssl *ssl = ctx;
    *tnext = ssl->cb_next;
}

void mender_http_transport_ssl_create(struct mender_http_transport_ssl *ssl,
    struct mender_platform_eventloop *el, const void *der, size_t der_sz,
    const int *ciphersuites)
{
    memset(ssl, 0, sizeof(*ssl));
    ssl->el = el;
    ssl->der_buf = der;
    ssl->der_sz = der_sz;
    ssl->ciphersuites = ciphersuites;
    ssl->state = MENDER_HTTP_TRANSPORT_SSL_STATE_READY;
    ssl->t.set_read_cb_enabled = transport_set_read_cb_enabled;
    ssl->t.connect = transport_connect;
    ssl->t.read = transport_read;
    ssl->t.write = transport_write;
    ssl->t.close = transport_close;

    ssl->eventloop_slot.ctx = ssl;
    ssl->eventloop_slot.fd = -1;
    ssl->eventloop_slot.flags = 0;
    ssl->eventloop_slot.cb = data_cb;

    ssl->cb_next = MENDER_TIME_INFINITE;
    ssl->eventloop_cb.ctx = ssl;
    ssl->eventloop_cb.cb = event_cb;
    ssl->eventloop_cb.get_timeout = event_cb_get_timeout;
    mender_eventloop_register_loop_cb(ssl->el, &ssl->eventloop_cb);
}
