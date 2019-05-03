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

#ifndef MENDER_PLATFORM_TRANSPORT_SSL_H
#define MENDER_PLATFORM_TRANSPORT_SSL_H

#include <mender/transport.h>
#include <mender/platform/eventloop.h>
#include <mender/platform/http_transport_common.h>

#include <mbedtls/platform.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>

enum mender_http_transport_ssl_state {
    MENDER_HTTP_TRANSPORT_SSL_STATE_READY,
    MENDER_HTTP_TRANSPORT_SSL_STATE_INITIALIZED,
    MENDER_HTTP_TRANSPORT_SSL_STATE_CONNECT,
    MENDER_HTTP_TRANSPORT_SSL_STATE_HANDSHAKE,
    MENDER_HTTP_TRANSPORT_SSL_STATE_CONNECTED,
};

struct mender_http_transport_ssl {
    struct mender_http_transport t;
    struct eventloop_slot_fd eventloop_slot;
    struct mender_platform_eventloop *el;
    const void *der_buf;
    size_t der_sz;

    struct eventloop_slot_loop eventloop_cb;
    mender_time_t cb_next;

    enum mender_http_transport_ssl_state state;
    mbedtls_net_context netctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ctx;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    struct mender_http_transport_connect_ctx connect_ctx;
    const char *host;

    const void *write_buf;
    size_t write_len;
};

void mender_http_transport_ssl_create(struct mender_http_transport_ssl *ssl, struct mender_platform_eventloop *el, const void *der, size_t der_sz);

#endif /* MENDER_PLATFORM_TRANSPORT_SSL_H */
