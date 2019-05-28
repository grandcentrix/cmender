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

#define fake_store ((struct mender_store*)0x8BADF00D)
#define fake_authmgr ((struct mender_authmgr*)0xABADBABE)
#define fake_stack ((struct mender_stack*)0xBAADA555)
#define fake_client ((struct mender_http_client*)0xDEADBAAD)
#define fake_device ((struct mender_device*)0xBAAAAAAD)
#define fake_inventroy ((struct mender_inventory_data*)0xBAD22222)

static const char *fake_current_artifact_name = "fake-artifact";
static const char *fake_device_type = "fake-device";
static const char *fake_server_url = "https://fake-server.tld";
static const mender_duration_t fake_duration = 1337;
static const mender_time_t fake_time = 4223;

static mender_time_t get_update_check_time_cb(void) {
    function_called();

    return fake_time;
}

static void setup_mender(void) {
    expect_mender_client_auth_create(&mender_instance.client_auth, fake_client, fake_authmgr);
    expect_mender_client_inventory_create(&mender_instance.client_inventory, fake_client, fake_authmgr);
    expect_mender_client_update_create(&mender_instance.client_update, fake_client, fake_authmgr);
    expect_mender_client_status_create(&mender_instance.client_status, fake_client, fake_authmgr);
    expect_mender_client_log_create(&mender_instance.client_log, fake_client, fake_authmgr);
    expect_mender_installer_create(&mender_instance.installer, fake_device, fake_stack, fake_device_type);

    mender_create(&mender_instance, fake_store, fake_authmgr,
            fake_stack, fake_client, fake_device,
            fake_inventroy,
            fake_current_artifact_name, fake_device_type, fake_server_url,
            fake_duration, get_update_check_time_cb,
            fake_duration, fake_duration);
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
    expect_mender_authmgr_is_authorized(fake_authmgr, 1);
    expect_cb((void*)0xbaadc0de, MERR_NONE);
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);

    // Test bootstrap failed
    setup_mender();
    expect_mender_authmgr_is_authorized(fake_authmgr, 0);
    expect_mender_authmgr_has_key(fake_authmgr, 0);
    expect_mender_authmgr_generate_key(fake_authmgr, (mender_err_t)0xd15ea5e);
    expect_cb((void*)0xbaadc0de, MENDER_ERR_FATAL((mender_err_t)0xd15ea5e));
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);

    // Authorization request failed
    setup_mender();
    expect_mender_authmgr_is_authorized(fake_authmgr, 0);
    expect_mender_authmgr_has_key(fake_authmgr, 0);
    expect_mender_authmgr_generate_key(fake_authmgr, MERR_NONE);
    expect_mender_client_auth_request(&(mender_instance.client_auth), fake_server_url,
        client_auth_cb, &mender_instance, (mender_err_t)0xd15ea5e);
    expect_cb((void*)0xbaadc0de, (mender_err_t)0xd15ea5e);
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);

    // Authorization request needed and successfull
    setup_mender();
    expect_mender_authmgr_is_authorized(fake_authmgr, 0);
    expect_mender_authmgr_has_key(fake_authmgr, 0);
    expect_mender_authmgr_generate_key(fake_authmgr, MERR_NONE);
    expect_mender_client_auth_request(&(mender_instance.client_auth), fake_server_url,
        client_auth_cb, &mender_instance, MERR_NONE);
    mender_authorize(&mender_instance, cb, (void*)0xbaadc0de);
    // mender_client_auth would call the cb if done, so it must set after successfull run inside the mender object
    assert_ptr_equal(mender_instance.auth_cb, cb);
    assert_ptr_equal(mender_instance.auth_cbctx, (void*)0xbaadc0de);
}

static void test_mender_auth_cb(void **state __unused) {
    const char *fake_token = "This is a fake token to be saved by the authmgr";

    // We are not authorized any longer, the auth token has to be removed
    setup_mender();
    mender_instance.auth_cb = cb;
    mender_instance.auth_cbctx = (void*)0xbaadc0de;
    expect_mender_authmgr_remove_auth_token(fake_authmgr, MERR_UNKNOWN);
    expect_mender_client_auth_finish_request(&mender_instance.client_auth);
    expect_cb((void*)0xbaadc0de, MERR_CLIENT_UNAUTHORIZED);
    client_auth_cb((void*)&mender_instance, MERR_CLIENT_UNAUTHORIZED, NULL, 0);

    // We got a new token, it is expected to be saved
    setup_mender();
    mender_instance.auth_cb = cb;
    mender_instance.auth_cbctx = (void*)0xbaadc0de;
    expect_mender_authmgr_set_token(fake_authmgr, (void*)fake_token, strlen(fake_token), MERR_NONE);
    expect_mender_client_auth_finish_request(&mender_instance.client_auth);
    expect_cb((void*)0xbaadc0de, MERR_NONE);
    client_auth_cb((void*)&mender_instance, MERR_NONE, (void*)fake_token, strlen(fake_token));
}

static void test_mender_check_update(void **state __unused) {
    // Test another request is running
    setup_mender();
    mender_instance.cb = (mender_on_result_t)0xdeadbeef;
    expect_cb((void*)0xbaadc0de, MERR_BUSY);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);

    // Test no/empty artifact_name
    setup_mender();
    mender_instance.current_artifact_name = NULL;
    expect_cb((void*)0xbaadc0de, MERR_NO_ARTIFACT_NAME);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);

    setup_mender();
    mender_instance.current_artifact_name = "";
    expect_cb((void*)0xbaadc0de, MERR_NO_ARTIFACT_NAME);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);

    // Test update check failed, e.g. client_update is busy
    setup_mender();
    expect_mender_client_update_get(&(mender_instance.client_update), fake_server_url,
        fake_current_artifact_name, fake_device_type, (struct mender_update_response*)0xdeadbeef,
        check_update_cb, (void*)&mender_instance, MERR_BUSY);
    expect_cb((void*)0xbaadc0de, MERR_BUSY);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);

    // Test update check success
    setup_mender();
    expect_mender_client_update_get(&(mender_instance.client_update), fake_server_url,
        fake_current_artifact_name, fake_device_type, (struct mender_update_response*)0xdeadbeef,
        check_update_cb, (void*)&mender_instance, MERR_NONE);
    mender_check_update(&mender_instance, (struct mender_update_response*)0xdeadbeef, cb, (void*)0xbaadc0de);
    // mender_check_update would call the cb if done
    assert_ptr_equal(mender_instance.cb, cb);
    assert_ptr_equal(mender_instance.cbctx, (void*)0xbaadc0de);
}

static void test_mender_check_update_cb(void **state __unused) {
    // We are not authorized any longer, the auth token has to be removed
    setup_mender();
    mender_instance.cb = cb;
    mender_instance.cbctx = (void*)0xbaadc0de;
    expect_mender_authmgr_remove_auth_token(fake_authmgr, MERR_UNKNOWN);
    // Authorization request needed and successfull
    expect_mender_authmgr_is_authorized(fake_authmgr, 0);
    expect_mender_authmgr_has_key(fake_authmgr, 0);
    expect_mender_authmgr_generate_key(fake_authmgr, MERR_NONE);
    expect_mender_client_auth_request(&(mender_instance.client_auth), fake_server_url,
        client_auth_cb, &mender_instance, MERR_NONE);
    check_update_cb((void*)&mender_instance, MERR_CLIENT_UNAUTHORIZED);
    // mender client_auth is expected to call the check_update_reauth_cb after the reauth attempt
    assert_ptr_equal(mender_instance.auth_cb, check_update_reauth_cb);

    // No updates avaible
    setup_mender();
    mender_instance.cb = cb;
    mender_instance.cbctx = (void*)0xbaadc0de;
    expect_cb((void*)0xbaadc0de, MERR_NOT_FOUND);
    check_update_cb((void*)&mender_instance, MERR_NOT_FOUND);

    // Got already installed artifact
    setup_mender();
    mender_instance.cb = cb;
    mender_instance.cbctx = (void*)0xbaadc0de;
    mender_instance.check_ur = &((struct mender_update_response){
            .artifact_name = "fake-artifact",
            .id = "fake-response"
            });
    expect_cb((void*)0xbaadc0de, MERR_EXISTS);
    check_update_cb((void*)&mender_instance, MERR_NONE);

    // Got new artifact
    setup_mender();
    mender_instance.cb = cb;
    mender_instance.cbctx = (void*)0xbaadc0de;
    mender_instance.check_ur = &((struct mender_update_response){
            .artifact_name = "new-artifact",
            .id = "fake-response"
            });
    expect_cb((void*)0xbaadc0de, MERR_NONE);
    check_update_cb((void*)&mender_instance, MERR_NONE);
}

static const struct CMUnitTest tests_mender[] = {
    cmocka_unit_test(test_mender_authorize),
    cmocka_unit_test(test_mender_auth_cb),
    cmocka_unit_test(test_mender_check_update),
    cmocka_unit_test(test_mender_check_update_cb),
};

static int setup(void **state __unused) {
    mender_authmgr_mocking_enabled = 1;
    mender_client_auth_mocking_enabled = 1;
    mender_client_update_mocking_enabled = 1;
    mender_client_inventory_mocking_enabled = 1;
    mender_client_status_mocking_enabled = 1;
    mender_client_log_mocking_enabled = 1;
    mender_installer_mocking_enabled = 1;
    return 0;
}

static int teardown(void **state __unused) {
    mender_authmgr_mocking_enabled = 0;
    mender_client_auth_mocking_enabled = 0;
    mender_client_update_mocking_enabled = 0;
    mender_client_inventory_mocking_enabled = 0;
    mender_client_status_mocking_enabled = 0;
    mender_client_log_mocking_enabled = 0;
    mender_installer_mocking_enabled = 0;
    return 0;
}

int mender_test_run_mender(void) {
    return cmocka_run_group_tests(tests_mender, setup, teardown);
}
