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

#ifndef MENDER_AUTHMGR_H
#define MENDER_AUTHMGR_H

#include <mender/error.h>
#include <mender/platform/types.h>
#include <mender/store.h>
#include <mender/keystore.h>
#include <mender/identity_data.h>

struct mender_authmgr {
    struct mender_store *store;
    struct mender_keystore *keystore;
    struct mender_identity_data *id;
};

void mender_authmgr_create(struct mender_authmgr *am,
        struct mender_store *store, struct mender_keystore *keystore,
        struct mender_identity_data *id);
int mender_authmgr_is_authorized(struct mender_authmgr *am);
int mender_authmgr_has_key(struct mender_authmgr *am);
mender_err_t mender_authmgr_remove_auth_token(struct mender_authmgr *am);
mender_err_t mender_authmgr_generate_key(struct mender_authmgr *am);
mender_err_t mender_authmgr_generate_authdata(struct mender_authmgr *am,
        char *buf, size_t bufsz, size_t *pactual,
        const char **pdata, size_t *pdatalen,
        const char **psig, size_t *psiglen,
        const char **ptoken, size_t *ptokenlen);
mender_err_t mender_authmgr_set_token(struct mender_authmgr *am,
        void *token, size_t tokensz);
mender_err_t mender_authmgr_get_token(struct mender_authmgr *am,
        void *token, size_t maxtokensz, size_t *pactual);

#endif /* MENDER_AUTHMGR_H */
