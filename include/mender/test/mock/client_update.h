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

#ifndef MENDER_TEST_MOCK_CLIENT_UPDATE_H
#define MENDER_TEST_MOCK_CLIENT_UPDATE_H

#include <mender/test/common.h>
#include <mender/platform/log.h>

extern int mender_client_update_mocking_enabled;

__unused static inline mender_err_t mender_client_update_get_mock(struct mender_client_update *u, const char *server,
        const char *artifact_name, const char *device_type, struct mender_update_response *ur,
        mender_client_update_get_cb_t cb, void *cbctx) {
    if (!mender_client_update_mocking_enabled)
        return mender_client_update_get_mock(u, server, artifact_name, device_type, ur, cb, cbctx);

    function_called();

    check_expected_ptr(u);
    check_expected(server);
    check_expected(artifact_name);
    check_expected(device_type);
    check_expected_ptr(ur);
    check_expected_ptr(cb);
    check_expected_ptr(cbctx);

    return mock_type(mender_err_t);
}

__unused static inline void mender_client_update_create_mock(struct mender_client_update *u, struct mender_http_client *client,
        struct mender_authmgr *authmgr) {
    if (!mender_client_update_mocking_enabled)
        return mender_client_update_create(u, client, authmgr);

    function_called();

    check_expected_ptr(u);
    check_expected_ptr(client);
    check_expected_ptr(authmgr);
}

__unused static inline mender_err_t mender_client_update_fetch_mock(struct mender_client_update *u, const char *url,
        mender_duration_t max_wait,
        struct mender_client_update_fetch_cb *cb, void *cbctx) {
    if (!mender_client_update_mocking_enabled)
        return mender_client_update_fetch(u, url, max_wait, cb, cbctx);

    function_called();

    check_expected_ptr(u);
    check_expected(url);
    check_expected(max_wait);
    check_expected_ptr(cb);
    check_expected_ptr(cbctx);

    return mock_type(mender_err_t);
}

__unused static inline void mender_client_update_reset_mock(struct mender_client_update *u) {
    if (!mender_client_update_mocking_enabled)
        return mender_client_update_reset(u);

    function_called();

    check_expected_ptr(u);
}

__unused static inline void mender_client_update_data_sent_mock(void *ctx, struct mender_http_client *c) {
    if (!mender_client_update_mocking_enabled)
        return mender_client_update_data_sent(ctx, c);

    function_called();

    check_expected_ptr(ctx);
    check_expected_ptr(c);
}

#define mender_client_update_get mender_client_update_get_mock
#define mender_client_update_create mender_client_update_create_mock
#define mender_client_update_fetch mender_client_update_fetch_mock
#define mender_client_update_reset mender_client_update_reset_mock
#define mender_client_update_data_sent mender_client_update_data_sent_mock

__unused static void expect_mender_client_update_get(struct mender_client_update *the_u, const char *the_server,
        const char *the_artifact_name, const char *the_device_type, struct mender_update_response *the_ur,
        mender_client_update_get_cb_t the_cb, void *the_cbctx, mender_err_t ret) {
    expect_function_call(mender_client_update_get_mock);

    expect_value(mender_client_update_get_mock, u, cast_ptr_to_largest_integral_type(the_u));
    expect_string(mender_client_update_get_mock, server, the_server);
    expect_string(mender_client_update_get_mock, artifact_name, the_artifact_name);
    expect_string(mender_client_update_get_mock, device_type, the_device_type);
    expect_value(mender_client_update_get_mock, ur, cast_ptr_to_largest_integral_type(the_ur));
    expect_value(mender_client_update_get_mock, cb, cast_ptr_to_largest_integral_type(the_cb));
    expect_value(mender_client_update_get_mock, cbctx, cast_ptr_to_largest_integral_type(the_cbctx));

    will_return(mender_client_update_get_mock, ret);
}

__unused static void expect_mender_client_update_create(struct mender_client_update *the_u, struct mender_http_client *the_client,
        struct mender_authmgr *the_authmgr) {
    expect_function_call(mender_client_update_create_mock);

    expect_value(mender_client_update_create_mock, u, cast_ptr_to_largest_integral_type(the_u));
    expect_value(mender_client_update_create_mock, client, cast_ptr_to_largest_integral_type(the_client));
    expect_value(mender_client_update_create_mock, authmgr, cast_ptr_to_largest_integral_type(the_authmgr));
}

__unused static void expect_mender_client_update_fetch(struct mender_client_update *the_u, const char *the_url,
        mender_duration_t the_max_wait,
        struct mender_client_update_fetch_cb *the_cb, void *the_cbctx, mender_err_t ret) {
    expect_function_call(mender_client_update_fetch_mock);

    expect_value(mender_client_update_fetch_mock, u, cast_ptr_to_largest_integral_type(the_u));
    expect_string(mender_client_update_fetch_mock, url, the_url);
    expect_value(mender_client_update_fetch_mock, max_wait, the_max_wait);
    expect_value(mender_client_update_fetch_mock, cb, cast_ptr_to_largest_integral_type(the_cb));
    expect_value(mender_client_update_fetch_mock, cbctx, cast_ptr_to_largest_integral_type(the_cbctx));

    will_return(mender_client_update_fetch_mock, ret);
}

#endif /* MENDER_TEST_MOCK_CLIENT_UPDATE_H */
