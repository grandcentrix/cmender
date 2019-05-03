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

#define KEY_SIZE 3072
#define EXPONENT 65537

static const char *keystore_pers = "mender_keystore";

enum output_format {
    FORMAT_PEM,
    FORMAT_DER
};

static int write_private_key(mbedtls_pk_context *key, const char *output_file, enum output_format format)
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
    if (format == FORMAT_PEM) {
        ret = mbedtls_pk_write_key_pem(key, output_buf, 16000);
        if (ret != 0)
            return ret;

        len = strlen((char*)output_buf);
    }
    else if(format == FORMAT_DER) {
        ret = mbedtls_pk_write_key_der(key, output_buf, 16000);
        if (ret < 0)
            return ret;

        len = ret;
        c = output_buf + sizeof(output_buf) - len;
    }
    else {
        LOGE("invalid output format: %d", format);
        return -1;
    }

    f = fopen( output_file, "wb");
    if (f == NULL)
        return -1;

    if (fwrite( c, 1, len, f ) != len) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

mender_err_t mender_keystore_load(struct mender_keystore *ks) {
    int rc;

    mbedtls_pk_init(&ks->key);
    rc = mbedtls_pk_parse_keyfile(&ks->key, ks->path, "");
    if (rc != 0) {
        LOGE("Could not parse keyfile");
        mbedtls_pk_free(&ks->key);

        if (rc == MBEDTLS_ERR_PK_FILE_IO_ERROR)
            return MERR_KEYSTORE_NOKEYS;

        return MERR_UNKNOWN;
    }

    ks->has_key = 1;

    return MERR_NONE;
}

mender_err_t mender_keystore_save(struct mender_keystore *ks) {
    int rc;

    if (!ks->has_key)
        return MERR_UNKNOWN;

    rc = write_private_key(&ks->key, ks->path, FORMAT_DER);
    if (rc) {
        LOGE("failed to write private key");
        return MERR_UNKNOWN;
    }

    return MERR_NONE;
}

int mender_keystore_has_key(struct mender_keystore *ks) {
    return !!ks->has_key;
}

mender_err_t mender_keystore_generate(struct mender_keystore *ks) {
    mender_err_t ret;
    int rc;
    char buf[1024];
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

    if (ks->has_key) {
        LOGE("we already have a key");
        return MERR_UNKNOWN;
    }

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
    mbedtls_pk_init(&ks->key);
    memset(buf, 0, sizeof(buf));

    rc = mbedtls_pk_setup(&ks->key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (rc) {
        LOGE("mbedtls_pk_setup returned -0x%04x", -rc);
        ret = MERR_UNKNOWN;
        goto exit;
    }

    rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ks->key), mbedtls_ctr_drbg_random,
            &ks->ctr_drbg, KEY_SIZE, EXPONENT);
    if (rc != 0) {
        LOGE("mbedtls_rsa_gen_key returned -0x%04x", -rc);
        ret = MERR_UNKNOWN;
        goto exit;
    }

    ret = MERR_NONE;
    ks->has_key = 1;

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

    if (ret) {
        mbedtls_pk_free(&ks->key);
    }

    return ret;
}

mender_err_t mender_keystore_sign(struct mender_keystore *ks, const void *data, size_t datasize,
        char *sign, size_t maxsignsz, size_t *pactual)
{
    int rc;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;

    if (!ks->has_key)
        return MERR_UNKNOWN;

    rc = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, datasize, hash);
    if (rc != 0) {
        LOGE("Could not hash input");
        return MERR_UNKNOWN;
    }

    rc = mbedtls_pk_sign(&ks->key, MBEDTLS_MD_SHA256, hash, 0, buf, &olen,
                         mbedtls_ctr_drbg_random, &ks->ctr_drbg);
    if (rc != 0) {
        LOGE("mbedtls_pk_sign returned -0x%04x\n", -rc);
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

    if (!ks->has_key)
        return MERR_UNKNOWN;

    rc = mbedtls_pk_write_pubkey_pem(&ks->key, (unsigned char*)pem, maxpemsize);
    if (rc)
        return MERR_UNKNOWN;

    *pactual = strlen(pem);
    return MERR_NONE;
}

mender_err_t mender_platform_keystore_create(struct mender_keystore *ks,
        const char *path)
{
    int rc;

    memset(ks, 0, sizeof(*ks));
    ks->path = path;
    ks->has_key = 0;

    mbedtls_entropy_init(&ks->entropy);
    mbedtls_ctr_drbg_init(&ks->ctr_drbg);

    rc = mbedtls_ctr_drbg_seed(&ks->ctr_drbg, mbedtls_entropy_func,
            &ks->entropy, (const unsigned char *) keystore_pers, strlen(keystore_pers));
    if (rc) {
        LOGE("mbedtls_ctr_drbg_seed returned -0x%04x\n", -rc);
        return MERR_UNKNOWN;
    }

    return MERR_NONE;
}
