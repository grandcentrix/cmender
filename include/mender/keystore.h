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

#ifndef MENDER_KEYSTORE_H
#define MENDER_KEYSTORE_H

#include <mender/error.h>

struct mender_keystore;

mender_err_t mender_keystore_load(struct mender_keystore *ks);
mender_err_t mender_keystore_save(struct mender_keystore *ks);
int mender_keystore_has_key(struct mender_keystore *ks);
mender_err_t mender_keystore_generate(struct mender_keystore *ks);
mender_err_t mender_keystore_sign(struct mender_keystore *ks, const void *data, size_t datasize,
        char *sign, size_t maxsignsz, size_t *pactual);
mender_err_t mender_keystore_get_public_pem(struct mender_keystore *ks, char *pem, size_t maxpemsize, size_t *pactual);
mender_err_t mender_keystore_get_keytype(struct mender_keystore *ks, const char **ptype);

#endif /* MENDER_KEYSTORE_H */
