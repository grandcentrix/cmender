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

#ifndef MENDER_PLATFORM_KEYSTORE_H
#define MENDER_PLATFORM_KEYSTORE_H

#include <mender/keystore.h>
#include <mender/store.h>

#ifdef CONFIG_MENDER_PLATFORM_KEYSTORE_ED25519
#include <sodium.h>
#else
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#endif

struct mender_keystore {
    const char *path;

    int has_key;

#ifdef CONFIG_MENDER_PLATFORM_KEYSTORE_ED25519
    unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
#else
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
#endif
};

mender_err_t mender_platform_keystore_create(struct mender_keystore *keystore,
    const char *path);

#endif /* MENDER_PLATFORM_KEYSTORE_H */
