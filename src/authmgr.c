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

#include <mender/authmgr.h>
#include <mender/internal/compiler.h>
#include <mender/utils.h>
#include <mender/platform/log.h>

static const char *auth_token_name = "authtoken";

int mender_authmgr_is_authorized(struct mender_authmgr *am) {
    return mender_store_has(am->store, auth_token_name);
}

mender_err_t mender_authmgr_generate_authdata(struct mender_authmgr *am,
        char *buf, size_t bufsz, size_t *pactual,
        const char **pdata, size_t *pdatalen,
        const char **psig, size_t *psiglen,
        const char **ptoken, size_t *ptokenlen)
{
    int rc;
    mender_err_t merr;
    size_t actual;
    size_t pos = 0;
    const char *token;
    size_t tokenlen;
    size_t data_start;
    const char *data;
    size_t datalen;
    const char *sig;
    size_t siglen;
    const char *keytype = NULL;

    merr = mender_keystore_get_keytype(am->keystore, &keytype);
    if (merr) {
        LOGE("can't get keytype: %08x", merr);
        return merr;
    }

    /* get default token */
    token = buf + pos;
    rc = snprintf(buf + pos, bufsz - pos, "dummy");
    if (rc < 0 || rc >= (ssize_t)(bufsz - pos))
        return MERR_BUFFER_TOO_SMALL;
    tokenlen = (size_t)rc;
    pos += rc + 1;

    data = buf + pos;
    data_start = pos;
    rc = snprintf(buf + pos, bufsz - pos, "{\"id_data\":\"");
    if (rc < 0 || rc >= (ssize_t)(bufsz - pos))
        return MERR_BUFFER_TOO_SMALL;
    pos += rc;

    /* write id_data */
    merr = mender_identity_data_write(am->id, buf + pos, bufsz - pos, &actual);
    if (merr)
        return merr;
    
    merr = mender_json_encode_str_inplace(buf + pos, bufsz - pos, &actual);
    if (merr)
        return merr;
    pos += actual;

    /* write token */
    rc = snprintf(buf + pos, bufsz - pos, "\",\"tenant_token\":\"");
    if (rc < 0 || rc >= (ssize_t)(bufsz - pos))
        return MERR_BUFFER_TOO_SMALL;
    pos += rc;

    rc = snprintf(buf + pos, bufsz - pos, "%s", token);
    if (rc < 0 || rc >= (ssize_t)(bufsz - pos))
        return MERR_BUFFER_TOO_SMALL;

    merr = mender_json_encode_str_inplace(buf + pos, bufsz - pos, &actual);
    if (merr)
        return merr;
    pos += actual;

    /* write pubkey */
    rc = snprintf(buf + pos, bufsz - pos, "\",\"pubkey\":\"");
    if (rc < 0 || rc >= (ssize_t)(bufsz - pos))
        return MERR_BUFFER_TOO_SMALL;
    pos += rc;

    merr = mender_keystore_get_public_pem(am->keystore, buf + pos, bufsz - pos, &actual);
    if (merr)
        return merr;

    merr = mender_json_encode_str_inplace(buf + pos, bufsz - pos, &actual);
    if (merr)
        return merr;
    pos += actual;

    if (keytype) {
        /* write pubkeytype */
        rc = snprintf(buf + pos, bufsz - pos, "\",\"pubkeytype\":\"");
        if (rc < 0 || rc >= (ssize_t)(bufsz - pos))
            return MERR_BUFFER_TOO_SMALL;
        pos += rc;

        rc = snprintf(buf + pos, bufsz - pos, "%s", keytype);
        if (rc < 0 || rc >= (ssize_t)(bufsz - pos))
            return MERR_BUFFER_TOO_SMALL;

        merr = mender_json_encode_str_inplace(buf + pos, bufsz - pos, &actual);
        if (merr)
            return merr;
        pos += actual;
    }

    rc = snprintf(buf + pos, bufsz - pos, "\"}");
    if (rc < 0 || rc >= (ssize_t)(bufsz - pos))
        return MERR_BUFFER_TOO_SMALL;
    pos += rc;
    datalen = pos - data_start;
    pos++;

    /* sign */
    sig = buf + pos;
    merr = mender_keystore_sign(am->keystore, data, datalen, buf + pos, bufsz - pos, &actual);
    if (merr)
        return merr;
    siglen = actual;
    pos += actual + 1;

    *ptoken = token;
    *ptokenlen = tokenlen;
    *pdata = data;
    *pdatalen = datalen;
    *psig = sig;
    *psiglen = siglen;
    *pactual = pos;

    return MERR_NONE;
}

mender_err_t mender_authmgr_remove_auth_token(struct mender_authmgr *am) {
    /* remove token only if we have one */
    if (mender_store_has(am->store, auth_token_name)) {
        return mender_store_remove(am->store, auth_token_name);
    }

    return MERR_NONE;
}

mender_err_t mender_authmgr_generate_key(struct mender_authmgr *am) {
    mender_err_t merr;

    merr = mender_keystore_generate(am->keystore);
    if (merr) {
        LOGE("failed to generate device key: %u", merr);
        return merr;
    }

    merr = mender_keystore_save(am->keystore);
    if (merr) {
        LOGE("failed to save device key: %u", merr);
        return MENDER_ERR_FATAL(merr);
    }

    return MERR_NONE;
}

int mender_authmgr_has_key(struct mender_authmgr *am) {
	return mender_keystore_has_key(am->keystore);
}

void mender_authmgr_create(struct mender_authmgr *am,
        struct mender_store *store, struct mender_keystore *keystore,
        struct mender_identity_data *id)
{
    mender_err_t merr;

    am->store = store;
    am->keystore = keystore;
    am->id = id;

    merr = mender_keystore_load(keystore);
    if (merr && MENDER_ERR_VAL(merr) != MERR_KEYSTORE_NOKEYS) {
        LOGE("failed to load device keys: %u", merr);
        /*
         * Otherwise ignore error returned from Load() call. It will
         * just result in an empty keyStore which in turn will cause
         * regeneration of keys.
         */
    }
}

mender_err_t mender_authmgr_set_token(struct mender_authmgr *am,
        void *token, size_t tokensz)
{
    mender_err_t merr;

    merr = mender_store_write_all(am->store, auth_token_name, token, tokensz);
    if (merr) {
        LOGE("failed to save auth token: %u", merr);
    }

    return merr;
}

mender_err_t mender_authmgr_get_token(struct mender_authmgr *am,
        void *token, size_t maxtokensz, size_t *pactual)
{
    mender_err_t merr;

    merr = mender_store_read_all(am->store, auth_token_name, token, maxtokensz, pactual);
    if (merr) {
        LOGE("failed to read auth token: %u", merr);
    }

    return merr;
}
