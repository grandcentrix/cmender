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

#ifndef MENDER_TEST_MOCK_CLIENT_AUTH_H
#define MENDER_TEST_MOCK_CLIENT_AUTH_H

#include <mender/test/common.h>
#include <mender/platform/log.h>

extern int mender_client_auth_mocking_enabled;

__unused static inline void mender_client_auth_create_mock(struct mender_client_auth *ca, struct mender_http_client *client,
        struct mender_authmgr *authmgr) {
    if (!mender_client_auth_mocking_enabled)
        return mender_client_auth_create_mock(ca, client, authmgr);

    function_called();

    check_expected_ptr(ca);
    check_expected_ptr(client);
    check_expected_ptr(authmgr);
}

__unused static inline mender_err_t mender_client_auth_request_mock(struct mender_client_auth *ca, const char *server,
        mender_client_auth_cb_t cb, void *cbctx) {
    if (!mender_client_auth_mocking_enabled)
        return mender_client_auth_request_mock(ca, server, cb, cbctx);

    function_called();

    check_expected_ptr(ca);
    check_expected(server);
    check_expected_ptr(cb);
    check_expected_ptr(cbctx);

    return mock_type(mender_err_t);
}

__unused static inline void mender_client_auth_finish_request_mock(struct mender_client_auth *ca) {
    if (!mender_client_auth_mocking_enabled)
        return mender_client_auth_finish_request_mock(ca);

    function_called();

    check_expected_ptr(ca);
}


#define mender_client_auth_create mender_client_auth_create_mock
#define mender_client_auth_request mender_client_auth_request_mock
#define mender_client_auth_finish_request mender_client_auth_finish_request_mock

__unused static void expect_mender_client_auth_request(struct mender_client_auth *the_ca, const char *the_server,
        mender_client_auth_cb_t the_cb, void *the_cbctx, mender_err_t ret) {
    expect_function_call(mender_client_auth_request_mock);

    expect_value(mender_client_auth_request_mock, ca, cast_ptr_to_largest_integral_type(the_ca));
    expect_string(mender_client_auth_request_mock, server, the_server);
    expect_value(mender_client_auth_request_mock, cb, cast_ptr_to_largest_integral_type(the_cb));
    expect_value(mender_client_auth_request_mock, cbctx, cast_ptr_to_largest_integral_type(the_cbctx));

    will_return(mender_client_auth_request_mock, ret);
}

__unused static void expect_mender_client_auth_create(struct mender_client_auth *the_ca, struct mender_http_client *the_client,
        struct mender_authmgr *the_authmgr) {
    expect_function_call(mender_client_auth_create_mock);

    expect_value(mender_client_auth_create_mock, ca, cast_ptr_to_largest_integral_type(the_ca));
    expect_value(mender_client_auth_create_mock, client, cast_ptr_to_largest_integral_type(the_client));
    expect_value(mender_client_auth_create_mock, authmgr, cast_ptr_to_largest_integral_type(the_authmgr));
}

__unused static void expect_mender_client_auth_finish_request(struct mender_client_auth *the_ca) {
    expect_function_call(mender_client_auth_finish_request_mock);

    expect_value(mender_client_auth_finish_request_mock, ca, cast_ptr_to_largest_integral_type(the_ca));
}

#endif /* MENDER_TEST_MOCK_CLIENT_AUTH_H */
