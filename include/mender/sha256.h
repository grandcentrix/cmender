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

#ifndef MENDER_SHA256_H
#define MENDER_SHA256_H

#include <mender/error.h>
#include <mender/platform/types.h>
#include <mender/platform/sha256.h>

mender_err_t mender_sha256_begin(struct mender_sha256_context *ctx);
mender_err_t mender_sha256_process(struct mender_sha256_context *ctx, const uint8_t *data, size_t len);
mender_err_t mender_sha256_end(struct mender_sha256_context *ctx, uint8_t *result);

#endif /* MENDER_SHA256_H */
