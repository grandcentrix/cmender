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

#ifndef MENDER_DEPLOYMENT_LOGGER_H
#define MENDER_DEPLOYMENT_LOGGER_H

#include <mender/error.h>

mender_err_t deployment_logger_enable(const char *id);
mender_err_t deployment_logger_log(const char *last_state_str, int last_state, int deployment_status, mender_err_t merr);
void deployment_logger_disable(void);
mender_err_t deployment_logger_get_logs(const char *deployment_id, const char **pdata);

#endif /* MENDER_DEPLOYMENT_LOGGER_H */
