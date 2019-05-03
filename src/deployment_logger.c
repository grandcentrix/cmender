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

#include <mender/deployment_logger.h>
#include <mender/internal/compiler.h>

#include <mender/platform/log.h>

static char deployment_log[128] = "Nothing logged, yet.";

mender_err_t deployment_logger_enable(const char *id __unused) {
    return MERR_NONE;
}

mender_err_t deployment_logger_log(const char *last_state_str, int last_state, int deployment_status, mender_err_t merr) {
    snprintf(deployment_log, sizeof(deployment_log), "State: %s(%i); Deployment status: %08x; Error code: %08x", last_state_str, last_state, deployment_status, merr);

    return MERR_NONE;
}

void deployment_logger_disable(void) {

}

mender_err_t deployment_logger_get_logs(const char *deployment_id __unused, const char **pdata) {
    *pdata = deployment_log;
    return MERR_NONE;
}
