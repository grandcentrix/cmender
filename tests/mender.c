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

#define FAKE_OLD_ARTIFACT_NAME "0.5.1"
#define FAKE_CURRENT_ARTIFACT_NAME "1.2.0"
#define FAKE_NEW_ARTIFACT_NAME "1.3.0"
#define FAKE_NONSEMVER_ARTIFACT_NAME "fake-artifact"

static const char *fake_current_artifact_name = FAKE_CURRENT_ARTIFACT_NAME;
static const char *fake_device_type = "fake-device";
static const char *fake_server_url = "https://fake-server.tld";
static const mender_duration_t fake_duration = 1337;
static const mender_time_t fake_time = 4223;

static mender_time_t get_update_check_time_cb(void) {
    function_called();

    return fake_time;
}

static const char fake_data[] = {
    0x2c, 0xad, 0x8c, 0xbb, 0x9b, 0x00, 0x5a, 0x96, 0x38, 0x29, 0x68, 0x85,
    0xe1, 0xd5, 0xcd, 0xe7, 0xc9, 0x25, 0x42, 0x00, 0x45, 0x0f, 0x10, 0x52,
    0xb3, 0x85, 0x3d, 0xee, 0x0f, 0x31, 0xb6, 0x05, 0x93, 0x31, 0xed, 0xed,
    0x86, 0x02, 0x63, 0x38, 0xc7, 0xb1, 0x00, 0x86, 0x94, 0x41, 0xf0, 0x81,
    0xd1, 0x1e, 0x87, 0x3c, 0x2f, 0xf6, 0x10, 0x63, 0x52, 0xb5, 0x12, 0xc0,
    0x14, 0xcb, 0xc6, 0xbc
};

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

    // Got artifact with non-semver name
    setup_mender();
    mender_instance.cb = cb;
    mender_instance.cbctx = (void*)0xbaadc0de;
    mender_instance.check_ur = &((struct mender_update_response){
            .artifact_name = FAKE_NONSEMVER_ARTIFACT_NAME,
            .id = "fake-response"
            });
    expect_cb((void*)0xbaadc0de, MERR_VERSION_INVALID);
    check_update_cb((void*)&mender_instance, MERR_NONE);

    // Got already installed artifact
    setup_mender();
    mender_instance.cb = cb;
    mender_instance.cbctx = (void*)0xbaadc0de;
    mender_instance.check_ur = &((struct mender_update_response){
            .artifact_name = FAKE_CURRENT_ARTIFACT_NAME,
            .id = "fake-response"
            });
    expect_cb((void*)0xbaadc0de, MERR_EXISTS);
    check_update_cb((void*)&mender_instance, MERR_NONE);

    // Got older artifact
    setup_mender();
    mender_instance.cb = cb;
    mender_instance.cbctx = (void*)0xbaadc0de;
    mender_instance.check_ur = &((struct mender_update_response){
            .artifact_name = FAKE_OLD_ARTIFACT_NAME,
            .id = "fake-response"
            });
    expect_cb((void*)0xbaadc0de, MERR_VERSION_OLD);
    check_update_cb((void*)&mender_instance, MERR_NONE);

    // Got new artifact
    setup_mender();
    mender_instance.cb = cb;
    mender_instance.cbctx = (void*)0xbaadc0de;
    mender_instance.check_ur = &((struct mender_update_response){
            .artifact_name = FAKE_NEW_ARTIFACT_NAME,
            .id = "fake-response"
            });
    expect_cb((void*)0xbaadc0de, MERR_NONE);
    check_update_cb((void*)&mender_instance, MERR_NONE);
}

static void test_mender_fetch_update(void **state __unused) {
    struct mender mender_instance_backup;
    mender_err_t ret;

    // Test another auth request is running
    setup_mender();
    mender_instance.cb = (mender_on_result_t)0xdeadbeef;
    expect_cb((void*)0xbaadc0de, MERR_BUSY);
    mender_fetch_update(&mender_instance, "https://fake-download-url.com/", "fake-new-artifact",  cb, (void*)0xbaadc0de);

    // Test http client failed
    setup_mender();
    expect_mender_client_update_fetch(&mender_instance.client_update, "https://fake-download-url.com/", fake_duration,
        &mender_instance.fetch_update_cb, &mender_instance, MERR_BUSY);
    expect_cb((void*)0xbaadc0de, MERR_BUSY);
    mender_fetch_update(&mender_instance, "https://fake-download-url.com/", "fake-new-artifact",  cb, (void*)0xbaadc0de);

    // Test update fetch success
    setup_mender();
    expect_mender_client_update_fetch(&mender_instance.client_update, "https://fake-download-url.com/", fake_duration,
        &mender_instance.fetch_update_cb, &mender_instance, MERR_NONE);
    mender_fetch_update(&mender_instance, "https://fake-download-url.com/", "fake-new-artifact",  cb, (void*)0xbaadc0de);

    assert_ptr_equal(mender_instance.cb, cb);
    assert_ptr_equal(mender_instance.cbctx, (void*)0xbaadc0de);

    // Test callbacks
    // Test mender_fetchupdate_on_init_success
    expect_mender_installer_begin(&mender_instance.installer, "fake-new-artifact", MERR_NONE);
    ret = mender_fetchupdate_on_init_success(&mender_instance);
    assert_int_equal(ret, MERR_NONE);

    // Test mender_fetchupdate_on_data
    expect_mender_installer_process_data(&mender_instance.installer, fake_data, sizeof(fake_data), MERR_NONE);
    ret = mender_fetchupdate_on_data(&mender_instance, fake_data, sizeof(fake_data));
    assert_int_equal(ret, MERR_NONE);

    // Back up our mender instance for later use
    memcpy(&mender_instance_backup, &mender_instance, sizeof(struct mender));

    // Test mender_fetchupdate_on_finish
    expect_mender_installer_finish(&mender_instance.installer, MERR_NONE);
    expect_cb((void*)0xbaadc0de, MERR_NONE);
    mender_fetchupdate_on_finish(&mender_instance, MERR_NONE);

    // Test mender_fetchupdate_on_finish gets errors passed through
    memcpy(&mender_instance, &mender_instance_backup, sizeof(struct mender));
    expect_cb((void*)0xbaadc0de, MERR_UNKNOWN);
    mender_fetchupdate_on_finish(&mender_instance, MERR_UNKNOWN);

    // Test mender_fetchupdate_on_finish gets installers errors passed through
    memcpy(&mender_instance, &mender_instance_backup, sizeof(struct mender));
    expect_mender_installer_finish(&mender_instance.installer, MERR_INSTALL_NOT_SUCCESSFULL);
    expect_cb((void*)0xbaadc0de, MERR_INSTALL_NOT_SUCCESSFULL);
    mender_fetchupdate_on_finish(&mender_instance, MERR_NONE);
}

static const struct CMUnitTest tests_mender[] = {
    cmocka_unit_test(test_mender_authorize),
    cmocka_unit_test(test_mender_auth_cb),
    cmocka_unit_test(test_mender_check_update),
    cmocka_unit_test(test_mender_check_update_cb),
    cmocka_unit_test(test_mender_fetch_update),
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
