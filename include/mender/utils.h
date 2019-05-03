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

#ifndef MENDER_UTILS_H
#define MENDER_UTILS_H

#include <mender/platform/types.h>
#include <mender/error.h>

static inline int mender_isdigit(int c) {
    return (c >= '0' && c <= '9');
}

static inline int mender_isxdigit(int c) {
    return ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));
}

int mender_hex2int(int c);
size_t mender_hex2bytes(const char *src, uint8_t *dst, size_t n);

mender_err_t mender_json_encode_str_inplace(char *buf, size_t maxsz, size_t *pactual);
mender_err_t mender_json_decode_str_inplace(char *buf, size_t sz, size_t *pnewsz);

#endif /* MENDER_UTILS_H */
