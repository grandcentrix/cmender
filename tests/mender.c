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

#include <mender/test/common.h>
#include <string.h>

static struct mender mender_instance;
//static struct mender_client_auth ca_instance;

static const char *server_url = "https://example.com/updates";

static void setup_mender(void) {
    memset(&mender_instance, 0, sizeof(mender_instance));
    mender_instance.server_url = server_url;
}

static void cb( void* cbctx, mender_err_t result ) {
    function_called();

    check_expected_ptr(cbctx);
    check_expected(result);
}

static void expect_cb(void *the_cbctx, mender_err_t the_result) {
    expect_function_call(cb);
    expect_value(cb, cbctx, cast_ptr_to_largest_integral_type(the_cbctx));
    expect_value(cb, result, the_result);
}

static void test_mender_authorize(void **state __unused) {
    // Test another auth request is running
    setup_mender();
    mender_instance.auth_cb = (mender_on_result_t)0xdeadbeef;
    expect_cb((void*)0xbaadc0de, MERR_BUSY);
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);

    // Test there is already valid auth data
    setup_mender();
    mender_instance.authmgr = (struct mender_authmgr*)0xdeadbeef;
    expect_mender_authmgr_is_authorized((struct mender_authmgr*)0xdeadbeef, 1);
    expect_cb((void*)0xbaadc0de, MERR_NONE);
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);

    // Test bootstrap failed
    setup_mender();
    mender_instance.authmgr = (struct mender_authmgr*)0xdeadbeef;
    expect_mender_authmgr_is_authorized((struct mender_authmgr*)0xdeadbeef, 0);
    expect_mender_authmgr_has_key((struct mender_authmgr*)0xdeadbeef, 0);
    expect_mender_authmgr_generate_key((struct mender_authmgr*)0xdeadbeef, (mender_err_t)0xd15ea5e);
    expect_cb((void*)0xbaadc0de, MENDER_ERR_FATAL((mender_err_t)0xd15ea5e));
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);

    // Authorization request failed
    setup_mender();
    mender_instance.authmgr = (struct mender_authmgr*)0xdeadbeef;
    expect_mender_authmgr_is_authorized((struct mender_authmgr*)0xdeadbeef, 0);
    expect_mender_authmgr_has_key((struct mender_authmgr*)0xdeadbeef, 0);
    expect_mender_authmgr_generate_key((struct mender_authmgr*)0xdeadbeef, MERR_NONE);
    expect_mender_client_auth_request(&(mender_instance.client_auth), server_url,
        client_auth_cb, &mender_instance, (mender_err_t)0xd15ea5e);
    expect_cb((void*)0xbaadc0de, (mender_err_t)0xd15ea5e);
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);

    // Authorization request needed and successfull
    setup_mender();
    mender_instance.authmgr = (struct mender_authmgr*)0xdeadbeef;
    expect_mender_authmgr_is_authorized((struct mender_authmgr*)0xdeadbeef, 0);
    expect_mender_authmgr_has_key((struct mender_authmgr*)0xdeadbeef, 0);
    expect_mender_authmgr_generate_key((struct mender_authmgr*)0xdeadbeef, MERR_NONE);
    expect_mender_client_auth_request(&(mender_instance.client_auth), server_url,
        client_auth_cb, &mender_instance, MERR_NONE);
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);
    // mender_client_auth would call the cb if done, so it must set after successfull run inside the mender object
    assert_ptr_equal(mender_instance.auth_cb, cb);
    assert_ptr_equal(mender_instance.auth_cbctx, (void*)0xbaadc0de);
}

static void test_mender_check_update(void **state __unused) {
    // Test another request is running
    setup_mender();
    mender_instance.cb = (mender_on_result_t)0xdeadbeef;
    expect_cb((void*)0xbaadc0de, MERR_BUSY);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);

    // Test no/empty artifact_name
    setup_mender();
    expect_cb((void*)0xbaadc0de, MERR_NO_ARTIFACT_NAME);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);

    setup_mender();
    mender_instance.current_artifact_name = "";
    expect_cb((void*)0xbaadc0de, MERR_NO_ARTIFACT_NAME);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);

    // Test update check failed
    setup_mender();
    mender_instance.current_artifact_name = "fake-artifact";
    mender_instance.device_type = "fake-device";
    mender_instance.server_url = "https://fake-server.com";
    expect_mender_client_update_get(&(mender_instance.client_update), "https://fake-server.com",
        "fake-artifact", "fake-device", (struct mender_update_response*)0xdeadbeef,
        check_update_cb, (void*)&mender_instance, (mender_err_t)0xd15ea5e);
    expect_cb((void*)0xbaadc0de, (mender_err_t)0xd15ea5e);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);

    // Test update check success
    setup_mender();
    mender_instance.current_artifact_name = "fake-artifact";
    mender_instance.device_type = "fake-device";
    mender_instance.server_url = "https://fake-server.com";
    expect_mender_client_update_get(&(mender_instance.client_update), "https://fake-server.com",
        "fake-artifact", "fake-device", (struct mender_update_response*)0xdeadbeef,
        check_update_cb, (void*)&mender_instance, MERR_NONE);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);
}

static const struct CMUnitTest tests_mender[] = {
    cmocka_unit_test(test_mender_authorize),
    cmocka_unit_test(test_mender_check_update),
};

static int setup(void **state __unused) {
    mender_authmgr_mocking_enabled = 1;
    mender_client_auth_mocking_enabled = 1;
    mender_client_update_mocking_enabled = 1;
    return 0;
}

static int teardown(void **state __unused) {
    mender_authmgr_mocking_enabled = 0;
    mender_client_auth_mocking_enabled = 0;
    mender_client_update_mocking_enabled = 0;
    return 0;
}

int mender_test_run_mender(void) {
    return cmocka_run_group_tests(tests_mender, setup, teardown);
}
