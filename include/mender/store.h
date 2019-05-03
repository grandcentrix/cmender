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

#ifndef MENDER_STORE_H
#define MENDER_STORE_H

#include <mender/error.h>
#include <mender/platform/types.h>

struct mender_store;

int mender_store_has(struct mender_store *store, const char *key);
mender_err_t mender_store_read_all(struct mender_store *store, const char *key, void *data,
        size_t maxlen, size_t *pactual);
mender_err_t mender_store_write_all(struct mender_store *store, const char *key, const void *data, size_t len);
mender_err_t mender_store_remove(struct mender_store *store, const char *key);

#endif /* MENDER_STORE_H */
