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

#include <mender/platform/keystore.h>
#include <mender/platform/log.h>
#include <mender/internal/compiler.h>
#include <mbedtls/base64.h>
#include <unistd.h>
#include <fcntl.h>

mender_err_t mender_keystore_load(struct mender_keystore *ks) {
    int fd;
    ssize_t nbytes;

    fd = open(ks->path, O_RDONLY);
    if (fd < 0) {
        return MERR_UNKNOWN;
    }

    nbytes = read(fd, ks->sk, sizeof(ks->sk));
    if (nbytes != (ssize_t)sizeof(ks->sk)) {
        goto err_close;
    }

    close(fd);
    ks->has_key = 1;

    return MERR_NONE;

err_close:
    close(fd);

    return MERR_UNKNOWN;
}

mender_err_t mender_keystore_save(struct mender_keystore *ks) {
    int fd;
    ssize_t nbytes;

    if (!ks->has_key)
        return MERR_UNKNOWN;

    fd = open(ks->path, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0) {
        return MERR_UNKNOWN;
    }

    nbytes = write(fd, ks->sk, sizeof(ks->sk));
    if (nbytes != (ssize_t)sizeof(ks->sk)) {
        goto err_close;
    }

    close(fd);
    return MERR_NONE;

err_close:
    close(fd);

    return MERR_UNKNOWN;
}

int mender_keystore_has_key(struct mender_keystore *ks) {
    return !!ks->has_key;
}

mender_err_t mender_keystore_generate(struct mender_keystore *ks) {
    int rc;
    unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];

    if (ks->has_key) {
        LOGE("we already have a key");
        return MERR_UNKNOWN;
    }

    rc = crypto_sign_ed25519_keypair(pk, ks->sk);
    memset(pk, 0, sizeof(pk));
    if (rc) {
        LOGE("crypto_sign_keypair returned %d", rc);
        return MERR_UNKNOWN;
    }

    ks->has_key = 1;
    return MERR_NONE;
}

mender_err_t mender_keystore_sign(struct mender_keystore *ks, const void *data, size_t datasize,
        char *sign, size_t maxsignsz, size_t *pactual)
{
    int rc;
    unsigned char buf[crypto_sign_ed25519_BYTES];
    unsigned long long olen = 0;

    if (!ks->has_key)
        return MERR_UNKNOWN;


    rc = crypto_sign_ed25519_detached(buf, &olen, data, datasize, ks->sk);
    if (rc) {
        LOGE("can't sign: %d", rc);
        return MERR_UNKNOWN;
    }

    rc = mbedtls_base64_encode((unsigned char *)sign, maxsignsz, pactual, buf, olen);
    if (rc) {
        return MERR_UNKNOWN;
    }

    return MERR_NONE;
}

mender_err_t mender_keystore_get_public_pem(struct mender_keystore *ks, char *pem, size_t maxpemsize,
        size_t *pactual)
{
    int rc;
    unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];

    if (!ks->has_key)
        return MERR_UNKNOWN;

    rc = crypto_sign_ed25519_sk_to_pk(pk, ks->sk);
    if (rc) {
        return MERR_UNKNOWN;
    }

    rc = mbedtls_base64_encode((unsigned char *)pem, maxpemsize, pactual, pk, sizeof(pk));
    if (rc) {
        return MERR_UNKNOWN;
    }

    return MERR_NONE;
}

mender_err_t mender_platform_keystore_create(struct mender_keystore *ks,
        const char *path)
{
    memset(ks, 0, sizeof(*ks));
    ks->path = path;
    ks->has_key = 0;

    return MERR_NONE;
}

mender_err_t mender_keystore_get_keytype(struct mender_keystore *ks __unused, const char **ptype) {
    *ptype = "ed25519";
    return MERR_NONE;
}
