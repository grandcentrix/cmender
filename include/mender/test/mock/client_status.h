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

#ifndef MENDER_TEST_MOCK_CLIENT_STATUS_H
#define MENDER_TEST_MOCK_CLIENT_STATUS_H

#include <mender/test/common.h>
#include <mender/platform/log.h>

extern int mender_client_status_mocking_enabled;

__unused static inline void mender_client_status_create_mock(struct mender_client_status *s, struct mender_http_client *client,
        struct mender_authmgr *authmgr) {
    if (!mender_client_status_mocking_enabled)
        return mender_client_status_create(s, client, authmgr);

    function_called();

    check_expected_ptr(s);
    check_expected_ptr(client);
    check_expected_ptr(authmgr);
}

__unused static inline mender_err_t mender_client_status_report_mock(struct mender_client_status *s, const char *server,
        const char *deployment_id, enum mender_deployment_status status,
        mender_client_status_cb_t cb, void *cbctx){
    if (!mender_client_status_mocking_enabled)
        return mender_client_status_report(s, server, deployment_id, status, cb, cbctx);

    function_called();

    check_expected_ptr(s);
    check_expected(server);
    check_expected(deployment_id);
    check_expected(status);
    check_expected_ptr(cb);
    check_expected_ptr(cbctx);

    return mock_type(mender_err_t);
}

#define mender_client_status_create mender_client_status_create_mock
#define mender_client_status_report mender_client_status_report_mock

__unused static void expect_mender_client_status_create(struct mender_client_status *the_s, struct mender_http_client *the_client,
        struct mender_authmgr *the_authmgr) {
    expect_function_call(mender_client_status_create_mock);

    expect_value(mender_client_status_create_mock, s, cast_ptr_to_largest_integral_type(the_s));
    expect_value(mender_client_status_create_mock, client, cast_ptr_to_largest_integral_type(the_client));
    expect_value(mender_client_status_create_mock, authmgr, cast_ptr_to_largest_integral_type(the_authmgr));
}

#endif /* MENDER_TEST_MOCK_CLIENT_STATUS_H */
