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

#include <mender/platform/identity_data.h>
#include <mender/internal/compiler.h>
#include <stdio.h>

mender_err_t mender_identity_data_write(struct mender_identity_data *id __unused, char *buf, size_t bufsz, size_t *pactual)
{
    int rc;

    rc = snprintf(buf, bufsz, "{\"mac\":\"%s\"}", id->mac_address);
    if (rc < 0)
        return MERR_UNKNOWN;
    *pactual = rc;

    if (rc >= (int)bufsz)
        return MERR_BUFFER_TOO_SMALL;

    return MERR_NONE;
}

void mender_platform_identity_data_create(struct mender_identity_data *pid, const char *mac_address) {
    memset(pid, 0, sizeof(*pid));
    pid->mac_address = mac_address;
}
