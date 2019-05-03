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

#include <mender/sha256.h>

static mender_err_t mender_sha256_free(struct mender_sha256_context *ctx);

mender_err_t mender_sha256_begin(struct mender_sha256_context *ctx) {
    mbedtls_md_init(&ctx->ctx);

    if (mbedtls_md_setup(&ctx->ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0))
        return MERR_UNKNOWN;

    ctx->initialized = true;

    if (mbedtls_md_starts(&ctx->ctx)) {
        mender_sha256_free(ctx);
        return MERR_UNKNOWN;
    }

    return MERR_NONE;
}

mender_err_t mender_sha256_process(struct mender_sha256_context *ctx, const uint8_t *data, size_t len) {
    if (mbedtls_md_update(&ctx->ctx, data, len)) {
        mender_sha256_free(ctx);
        return MERR_UNKNOWN;
    }

    return MERR_NONE;
}

mender_err_t mender_sha256_end(struct mender_sha256_context *ctx, uint8_t *result) {
    mender_err_t res = MERR_NONE;

    if (mbedtls_md_finish(&ctx->ctx, result)) {
        res = MERR_UNKNOWN;
    }

    mender_sha256_free(ctx);

    return res;
}

static mender_err_t mender_sha256_free(struct mender_sha256_context *ctx) {
    if (ctx->initialized) {
        mbedtls_md_free(&ctx->ctx);
        ctx->initialized = false;
    }

    return MERR_NONE;
}
