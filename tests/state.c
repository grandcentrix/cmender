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

static struct mender_statemachine sm;
static struct mender_update_response update;
static struct mender_statedata sd;
static struct mender_statedata rsd;
static struct mender_store *store = (void*) 0xdeadbeef;
static struct mender *mender = (void*) 0xd00dfeed;

#define FAKE_TIME 1000000000

static int iszerobuf(void *_p, size_t len) {
    size_t i;
    uint8_t *p = _p;

    for (i=0; i<len; i++) {
        if (p[i]) return 0;
    }

    return 1;
}

static void test_state_error(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    sm.current_state = MENDER_STATE_ERROR;
    sm.last_error = MERR_UNKNOWN;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_IDLE);
    assert_int_equal(sm.next_state_update, 0);

    sm.current_state = MENDER_STATE_ERROR;
    sm.last_error = MENDER_ERR_FATAL(MERR_UNKNOWN);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_DONE);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_update_error(void **state __unused) {
    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "fakeid");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    sm.current_state = MENDER_STATE_UPDATE_ERROR;
    sm.last_error = MERR_UNKNOWN;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_FAILURE);
    assert_int_equal(sm.next_state_update, 0);
}

static void update_report_do(void)
{
    mender_err_t err;
    const char *logs;

    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT);
    assert_int_equal(sm.next_state_update, 0);

    mender_report_update_status_expect(mender, sm.update.id, sm.deployment_status, MERR_NONE);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);

    if (sm.deployment_status == MENDER_DEPLOYMENT_STATUS_FAILURE) {
        assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS);
        assert_int_equal(sm.next_state_update, 0);

        /* TODO: verify log contents */
        err = deployment_logger_get_logs(sm.update.id, &logs);
        assert_int_equal(err, MERR_NONE);
        assert_non_null(logs);

        mender_upload_log_expect(mender, sm.update.id, logs, MERR_NONE);
        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
        assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS_ASYNC);
        assert_int_equal(sm.last_error, MERR_NONE);
        assert_int_equal(sm.next_state_update, 0);

        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    }

    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_COMPLETE);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_IDLE);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_update_report_status(void **state __unused) {
    mender_err_t err;
    const char *logs;
    mender_duration_t poll = 5;
    mender_duration_t retry = 1;
    int should_try;
    int i;

    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "fakeid");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    memset(&sd, 0, sizeof(sd));
    memcpy(sd.artifact_name, update.artifact_name, sizeof(sd.artifact_name));
    memcpy(sd.id, update.id, sizeof(sd.id));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_UPDATE_STATUS_REPORT;

    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);
    memcpy(&sm.update, &update, sizeof(update));

    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
    sm.deployment_status = sd.deployment_status;
    sm.current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
    update_report_do();

    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_SUCCESS;
    sm.deployment_status = sd.deployment_status;
    sm.current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
    update_report_do();

    /*
     * cancelled state should not wipe state data, for this pretend the reporting
     * fails and cancel
     */
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_SUCCESS;
    sm.deployment_status = sd.deployment_status;
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT);
    assert_int_equal(sm.next_state_update, 0);

    mender_report_update_status_expect(mender, sm.update.id, sm.deployment_status, MERR_UNKNOWN);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_STATUS_REPORT_RETRY);
    assert_int_equal(sm.next_state_update, 0);

    /* check retry attempts */
    should_try = max_sending_attempts(poll, retry, min_report_send_retries);

    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_SUCCESS;
    sm.deployment_status = sd.deployment_status;
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT);
    assert_int_equal(sm.next_state_update, 0);

    for (i=0; i < should_try; i++) {
        mender_report_update_status_expect(mender, sm.update.id, sm.deployment_status, MERR_UNKNOWN);
        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
        assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC);
        assert_int_equal(sm.last_error, MERR_UNKNOWN);
        assert_int_equal(sm.next_state_update, 0);

        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
        assert_int_equal(sm.current_state, MENDER_STATE_STATUS_REPORT_RETRY);
        assert_int_equal(sm.next_state_update, 0);

        mender_get_update_poll_interval_expect(mender, poll);
        mender_get_retry_poll_interval_expect(mender, retry);
        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
        assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT);
        assert_int_equal(sm.next_state_update, FAKE_TIME + retry);
        sm.next_state_update = 0;
    }

    /* next attempt should return an error */
    mender_report_update_status_expect(mender, sm.update.id, sm.deployment_status, MERR_UNKNOWN);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_STATUS_REPORT_RETRY);
    assert_int_equal(sm.next_state_update, 0);

    mender_get_update_poll_interval_expect(mender, poll);
    mender_get_retry_poll_interval_expect(mender, retry);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_REPORT_STATUS_ERROR);
    assert_int_equal(sm.next_state_update, 0);

    /* error sending logs */
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
    sm.deployment_status = sd.deployment_status;
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT);
    assert_int_equal(sm.next_state_update, 0);

    mender_report_update_status_expect(mender, sm.update.id, sm.deployment_status, MERR_NONE);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS);
    assert_int_equal(sm.next_state_update, 0);

    err = deployment_logger_get_logs(sm.update.id, &logs);
    assert_int_equal(err, MERR_NONE);
    assert_non_null(logs);

    for (i=0; i < should_try; i++) {
        mender_upload_log_expect(mender, sm.update.id, logs, MERR_UNKNOWN);

        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
        assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS_ASYNC);
        assert_int_equal(sm.last_error, MERR_UNKNOWN);
        assert_int_equal(sm.next_state_update, 0);

        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
        assert_int_equal(sm.current_state, MENDER_STATE_STATUS_REPORT_RETRY);
        assert_int_equal(sm.next_state_update, 0);

        mender_get_update_poll_interval_expect(mender, poll);
        mender_get_retry_poll_interval_expect(mender, retry);
        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
        assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS);
        assert_int_equal(sm.next_state_update, FAKE_TIME + retry);
        sm.next_state_update = 0;
    }

    /* next attempt should return an error */
    mender_upload_log_expect(mender, sm.update.id, logs, MERR_UNKNOWN);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS_ASYNC);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_STATUS_REPORT_RETRY);
    assert_int_equal(sm.next_state_update, 0);

    mender_get_update_poll_interval_expect(mender, poll);
    mender_get_retry_poll_interval_expect(mender, retry);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_REPORT_STATUS_ERROR);
    assert_int_equal(sm.next_state_update, 0);

    /*
     * pretend update was aborted at the backend, but was applied
     * successfully on the device
     */
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_SUCCESS;
    sm.deployment_status = sd.deployment_status;
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT);
    assert_int_equal(sm.next_state_update, 0);

    mender_report_update_status_expect(mender, sm.update.id, sm.deployment_status, MENDER_ERR_FATAL(MERR_DEPLOYMENT_ABORTED));
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC);
    assert_int_equal(sm.last_error, MENDER_ERR_FATAL(MERR_DEPLOYMENT_ABORTED));
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_REPORT_STATUS_ERROR);
    assert_int_equal(sm.next_state_update, 0);

    /* pretend update was aborted at the backend, along with local failure */
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
    sm.deployment_status = sd.deployment_status;
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT);
    assert_int_equal(sm.next_state_update, 0);

    mender_report_update_status_expect(mender, sm.update.id, sm.deployment_status, MENDER_ERR_FATAL(MERR_DEPLOYMENT_ABORTED));
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC);
    assert_int_equal(sm.last_error, MENDER_ERR_FATAL(MERR_DEPLOYMENT_ABORTED));
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_REPORT_STATUS_ERROR);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_idle(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    mender_store_remove_expect(store, state_data_key, MERR_NONE);
    mender_is_authorized_expect(mender, false);
    sm.current_state = MENDER_STATE_IDLE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_AUTHORIZE);
    assert_int_equal(sm.next_state_update, 0);

    mender_store_remove_expect(store, state_data_key, MERR_NONE);
    mender_is_authorized_expect(mender, true);
    sm.current_state = MENDER_STATE_IDLE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_CHECK_WAIT);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_init(void **state __unused) {
    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "fakeid");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    memset(&sd, 0, sizeof(sd));
    memcpy(sd.artifact_name, update.artifact_name, sizeof(sd.artifact_name));
    memcpy(sd.id, update.id, sizeof(sd.id));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_REBOOT;
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    mender_store_read_all_expect(store, state_data_key, NULL, 0, MERR_NOT_FOUND);
    sm.current_state = MENDER_STATE_INIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_IDLE);
    assert_int_equal(sm.next_state_update, 0);

    /*
     * pretend we have state data
     * have state data and have correct artifact name
     */
    mender_store_read_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_has_upgrade_expect(mender, true, MERR_NONE);
    sm.current_state = MENDER_STATE_INIT;
    memset(&sm.sd, 0, sizeof(sm.sd));
    memset(&sm.update, 0, sizeof(sm.update));
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_AFTER_REBOOT);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(memcmp(sm.update.artifact_name, update.artifact_name, sizeof(update.artifact_name)), 0);
    assert_int_equal(memcmp(sm.update.id, update.id, sizeof(update.id)), 0);

    /* error restoring state data */
    mender_store_read_all_expect(store, state_data_key, NULL, 0, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_INIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);

    /* pretend reading invalid state */
    mender_store_read_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_has_upgrade_expect(mender, false, MERR_NONE);
    sm.current_state = MENDER_STATE_INIT;
    memset(&sm.sd, 0, sizeof(sm.sd));
    memset(&sm.update, 0, sizeof(sm.update));
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(memcmp(sm.update.artifact_name, update.artifact_name, sizeof(update.artifact_name)), 0);
    assert_int_equal(memcmp(sm.update.id, update.id, sizeof(update.id)), 0);

    /* update-commit-leave behaviour */
    sd.state = MENDER_STATE_UPDATE_COMMIT;
    mender_store_read_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_has_upgrade_expect(mender, false, MERR_NONE);
    sm.current_state = MENDER_STATE_INIT;
    memset(&sm.sd, 0, sizeof(sm.sd));
    memset(&sm.update, 0, sizeof(sm.update));
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_IDLE);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_authorize(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* success */
    mender_authorize_expect(mender, MERR_NONE);
    sm.current_state = MENDER_STATE_AUTHORIZE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_AUTHORIZE_ASYNC);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_CHECK_WAIT);
    assert_int_equal(sm.next_state_update, 0);

    /* normal error */
    mender_authorize_expect(mender, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_AUTHORIZE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_AUTHORIZE_ASYNC);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_AUTHORIZE_WAIT);
    assert_int_equal(sm.next_state_update, 0);

    /* fatal error */
    mender_authorize_expect(mender, MENDER_ERR_FATAL(MERR_UNKNOWN));
    sm.current_state = MENDER_STATE_AUTHORIZE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_AUTHORIZE_ASYNC);
    assert_int_equal(sm.last_error, MENDER_ERR_FATAL(MERR_UNKNOWN));
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_inventory_update(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* error */
    mender_inventory_refresh_expect(mender, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_INVENTORY_UPDATE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_INVENTORY_UPDATE_ASYNC);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_CHECK_WAIT);
    assert_int_equal(sm.next_state_update, 0);

    /* success */
    mender_inventory_refresh_expect(mender, MERR_NONE);
    sm.current_state = MENDER_STATE_INVENTORY_UPDATE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_INVENTORY_UPDATE_ASYNC);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_CHECK_WAIT);
    assert_int_equal(sm.next_state_update, 0);

    /* no artifact name should fail */
    mender_inventory_refresh_expect(mender, MERR_NO_ARTIFACT_NAME);
    sm.current_state = MENDER_STATE_INVENTORY_UPDATE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_INVENTORY_UPDATE_ASYNC);
    assert_int_equal(sm.last_error, MERR_NO_ARTIFACT_NAME);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_authorize_wait(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    mender_get_retry_poll_interval_expect(mender, 60);
    sm.current_state = MENDER_STATE_AUTHORIZE_WAIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_AUTHORIZE);
    assert_int_equal(sm.next_state_update, FAKE_TIME + 60);
    sm.next_state_update = 0;
}

static void test_state_update_verify(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* has_upgrade failed */
    mender_has_upgrade_expect(mender, false, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_VERIFY;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.last_error, MERR_FAILED_TO_PERFORM_UPGRADE_CHECK);

    /* success */
    mender_has_upgrade_expect(mender, true, MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_VERIFY;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_COMMIT);
    assert_int_equal(sm.next_state_update, 0);

    /* upgrade not detected, should rollback */
    mender_has_upgrade_expect(mender, false, MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_VERIFY;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ROLLBACK);
    assert_int_equal(sm.next_state_update, 0);
    assert_false(sm.rollback_state.swap);
    assert_false(sm.rollback_state.reboot);
}

static void test_state_update_commit(void **state __unused) {
    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_UPDATE_COMMIT;
    strcpy(sd.artifact_name, "fakeid");
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* get_current_artifact_name failed */
    mender_get_current_artifact_name_expect(mender, NULL, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_COMMIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ROLLBACK);
    assert_int_equal(sm.next_state_update, 0);
    assert_false(sm.rollback_state.swap);
    assert_true(sm.rollback_state.reboot);

    /* pretend artifact name is different from expected; rollback happened */
    memcpy(sm.update.artifact_name, "fakeid", 7);
    mender_get_current_artifact_name_expect(mender, "not-fakeid", MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_COMMIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ROLLBACK);
    assert_int_equal(sm.next_state_update, 0);
    assert_false(sm.rollback_state.swap);
    assert_true(sm.rollback_state.reboot);

    /* commit failed */
    memcpy(sm.update.artifact_name, "fakeid", 7);
    mender_get_current_artifact_name_expect(mender, "fakeid", MERR_NONE);
    mender_commit_update_expect(mender, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_COMMIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ROLLBACK);
    assert_int_equal(sm.next_state_update, 0);
    assert_false(sm.rollback_state.swap);
    assert_true(sm.rollback_state.reboot);

    /* store failed */
    memcpy(sm.update.artifact_name, "fakeid", 7);
    mender_get_current_artifact_name_expect(mender, "fakeid", MERR_NONE);
    mender_commit_update_expect(mender, MERR_NONE);
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_COMMIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.next_state_update, 0);

    /* success */
    memcpy(sm.update.artifact_name, "fakeid", 7);
    mender_get_current_artifact_name_expect(mender, "fakeid", MERR_NONE);
    mender_commit_update_expect(mender, MERR_NONE);
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_COMMIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_update_check_wait(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* no inventory was sent; we should first send inventory */
    sm.next_state_update = 0;
    sm.last_inventory_update = 0;
    sm.last_update_check = 0;
    mender_get_update_poll_interval_expect(mender, 10);
    mender_get_inventory_poll_interval_expect(mender, 20);
    sm.current_state = MENDER_STATE_CHECK_WAIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_INVENTORY_UPDATE);
    assert_int_equal(sm.next_state_update, 0);

    /* now we have inventory sent, but never an update; should send update request */
    sm.next_state_update = 0;
    sm.last_inventory_update = FAKE_TIME;
    sm.last_update_check = 0;
    mender_get_update_poll_interval_expect(mender, 10);
    mender_get_inventory_poll_interval_expect(mender, 20);
    sm.current_state = MENDER_STATE_CHECK_WAIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_CHECK);
    assert_int_equal(sm.next_state_update, 0);

    /* inventory is closer than update; should wait for inventory first */
    sm.next_state_update = 0;
    sm.last_inventory_update = FAKE_TIME;
    sm.last_update_check = FAKE_TIME;
    mender_get_update_poll_interval_expect(mender, 20);
    mender_get_inventory_poll_interval_expect(mender, 10);
    sm.current_state = MENDER_STATE_CHECK_WAIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_INVENTORY_UPDATE);
    assert_int_equal(sm.next_state_update, FAKE_TIME + 10);

    /* update is closer than inventory; should wait for update first */
    sm.next_state_update = 0;
    sm.last_inventory_update = FAKE_TIME;
    sm.last_update_check = FAKE_TIME;
    mender_get_update_poll_interval_expect(mender, 10);
    mender_get_inventory_poll_interval_expect(mender, 20);
    sm.current_state = MENDER_STATE_CHECK_WAIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_CHECK);
    assert_int_equal(sm.next_state_update, FAKE_TIME + 10);
}

static void test_state_update_check(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* no update */
    mender_check_update_expect(mender, NULL, MERR_NOT_FOUND);
    sm.current_state = MENDER_STATE_UPDATE_CHECK;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_CHECK_ASYNC);
    assert_int_equal(sm.last_error, MERR_NOT_FOUND);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_CHECK_WAIT);
    assert_int_equal(sm.next_state_update, 0);

    /* pretend update check failed */
    mender_check_update_expect(mender, NULL, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_CHECK;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_CHECK_ASYNC);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);

    /* pretend we have an update */
    mender_check_update_expect(mender, NULL, MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_CHECK;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_CHECK_ASYNC);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_FETCH);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_update_check_same_image(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    mender_check_update_expect(mender, NULL, MERR_EXISTS);
    sm.current_state = MENDER_STATE_UPDATE_CHECK;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_CHECK_ASYNC);
    assert_int_equal(sm.last_error, MERR_EXISTS);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_ALREADY_INSTALLED);
}

static void test_state_update_fetch(void **state __unused) {
    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "test");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    mender_statemachine_create(&sm, store, mender);
    memcpy(&sm.update, &update, sizeof(update));
    will_return_always(mender_time_now_test, FAKE_TIME);

    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_UPDATE_FETCH;
    strcpy(sd.artifact_name, update.artifact_name);
    strcpy(sd.id, update.id);
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    /* can not store state data */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_FETCH;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_FAILURE);

    /* failed to report status */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_report_update_status_expect(mender, update.id, MENDER_DEPLOYMENT_STATUS_DOWNLOADING, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_FETCH;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);

    /* success */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_report_update_status_expect(mender, update.id, MENDER_DEPLOYMENT_STATUS_DOWNLOADING, MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_FETCH;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);
}

static void test_state_update_fetch_send_report_async(void **state __unused) {
    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "test");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    mender_statemachine_create(&sm, store, mender);
    memcpy(&sm.update, &update, sizeof(update));
    will_return_always(mender_time_now_test, FAKE_TIME);

    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_UPDATE_FETCH;
    strcpy(sd.artifact_name, update.artifact_name);
    strcpy(sd.id, update.id);
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    /* failed to fetch update */
    sm.last_error = MERR_NONE;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    mender_fetch_update_expect(mender, update.uri, update.artifact_name, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);

    /* success */
    sm.last_error = MERR_NONE;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    mender_fetch_update_expect(mender, update.uri, update.artifact_name, MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);

    /* normal error */
    sm.last_error = MERR_UNKNOWN;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    mender_fetch_update_expect(mender, update.uri, update.artifact_name, MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);

    /* fatal error */
    sm.last_error = MENDER_ERR_FATAL(MERR_UNKNOWN);
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    sm.current_state = MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_FAILURE);
}

static void test_state_update_fetch_send_dofetch_async(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* success */
    sm.last_error = MERR_NONE;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    sm.current_state = MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STORE);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);

    /* failed */
    sm.last_error = MERR_UNKNOWN;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    sm.current_state = MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_FETCH_STORE_RETRY_WAIT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);
}

static void test_state_update_fetch_retry(void **state __unused) {
}

static void test_state_update_store(void **state __unused) {
    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "test");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    mender_statemachine_create(&sm, store, mender);
    memcpy(&sm.update, &update, sizeof(update));
    will_return_always(mender_time_now_test, FAKE_TIME);

    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_UPDATE_STORE;
    strcpy(sd.artifact_name, update.artifact_name);
    strcpy(sd.id, update.id);
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    /* pretend writing update state data fails */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_STORE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_FAILURE);

    /* failed to report status */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_report_update_status_expect(mender, sm.update.id,
        MENDER_DEPLOYMENT_STATUS_DOWNLOADING, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_STORE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STORE_ASYNC_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);

    /* success */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_report_update_status_expect(mender, sm.update.id,
        MENDER_DEPLOYMENT_STATUS_DOWNLOADING, MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_STORE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STORE_ASYNC_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);
    assert_int_equal(sm.last_error, MERR_NONE);
}

static void test_state_update_store_async_report(void **state __unused) {
    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "test");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    mender_statemachine_create(&sm, store, mender);
    memcpy(&sm.update, &update, sizeof(update));
    will_return_always(mender_time_now_test, FAKE_TIME);

    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_UPDATE_STORE;
    strcpy(sd.artifact_name, update.artifact_name);
    strcpy(sd.id, update.id);
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    /* success */
    sm.last_error = MERR_NONE;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    sm.current_state = MENDER_STATE_UPDATE_STORE_ASYNC_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_INSTALL);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);

    /* normal error */
    sm.last_error = MERR_UNKNOWN;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    sm.current_state = MENDER_STATE_UPDATE_STORE_ASYNC_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_INSTALL);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_DOWNLOADING);

    /* fatal error */
    sm.last_error = MENDER_ERR_FATAL(MERR_UNKNOWN);
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    sm.current_state = MENDER_STATE_UPDATE_STORE_ASYNC_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_FAILURE);
}

static void test_state_update_install(void **state __unused) {
    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "test");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    mender_statemachine_create(&sm, store, mender);
    memcpy(&sm.update, &update, sizeof(update));
    will_return_always(mender_time_now_test, FAKE_TIME);

    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_UPDATE_STORE;
    strcpy(sd.artifact_name, update.artifact_name);
    strcpy(sd.id, update.id);
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    /* failed to report status */
    mender_report_update_status_expect(mender, sm.update.id,
        MENDER_DEPLOYMENT_STATUS_INSTALLING, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_UPDATE_INSTALL;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_INSTALLING);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);

    /* success */
    mender_report_update_status_expect(mender, sm.update.id,
        MENDER_DEPLOYMENT_STATUS_INSTALLING, MERR_NONE);
    sm.current_state = MENDER_STATE_UPDATE_INSTALL;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_INSTALLING);
    assert_int_equal(sm.last_error, MERR_NONE);
}

static void test_state_update_install_async_report(void **state __unused) {
    memset(&update, 0, sizeof(update));
    strcpy(update.uri, "https://localhost");
    update.is_compatible = 1;
    strcpy(update.artifact_name, "test");
    strcpy(update.id, "00000000-0000-4000-0000-000000000000");

    mender_statemachine_create(&sm, store, mender);
    memcpy(&sm.update, &update, sizeof(update));
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* normal error */
    mender_enable_updated_partition_expect(mender, MERR_NONE);
    sm.last_error = MERR_UNKNOWN;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_INSTALLING;
    sm.current_state = MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_REBOOT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_INSTALLING);

    /* fatal error */
    sm.last_error = MENDER_ERR_FATAL(MERR_UNKNOWN);
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_INSTALLING;
    sm.current_state = MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_ERROR);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_INSTALLING);

    /* failed to enable updated partition */
    mender_enable_updated_partition_expect(mender, MERR_UNKNOWN);
    sm.last_error = MERR_NONE;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_INSTALLING;
    sm.current_state = MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_ERROR);
    assert_int_equal(sm.last_error, MERR_UNKNOWN);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_INSTALLING);

    /* success */
    mender_enable_updated_partition_expect(mender, MERR_NONE);
    sm.last_error = MERR_NONE;
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_INSTALLING;
    sm.current_state = MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_REBOOT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_INSTALLING);
}

static void test_state_fetch_store_retry_wait(void **state __unused) {
    size_t i;

    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    sm.last_error = MERR_UNKNOWN;

    /*
     * Test for the twelve expected attempts:
     * (1m*3) + (2m*3) + (4m*3) + (5m*3)
     */
    for (i=0; i<12; i++) {
        LOGD("retry #%zu", i + 1);

        sm.next_state_update = 0;
        mender_get_update_poll_interval_expect(mender, 5 * 60);
        sm.current_state = MENDER_STATE_FETCH_STORE_RETRY_WAIT;
        assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
        assert_int_not_equal(sm.next_state_update, 0);
        assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_FETCH);
    }

    /* Final attempt should fail completely */
    sm.next_state_update = 0;
    mender_get_update_poll_interval_expect(mender, 5 * 60);
    sm.current_state = MENDER_STATE_FETCH_STORE_RETRY_WAIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_STATUS_REPORT);
    assert_int_equal(sm.deployment_status, MENDER_DEPLOYMENT_STATUS_FAILURE);

    /* for some weird reason we don't have an error */
    sm.last_error = MERR_NONE;
    sm.next_state_update = 0;
    mender_get_update_poll_interval_expect(mender, 5 * 60);
    sm.current_state = MENDER_STATE_FETCH_STORE_RETRY_WAIT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_ERROR);
}

static void test_state_reboot(void **state __unused) {
    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_REBOOT;
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* error during reboot */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_report_update_status_expect(mender, sm.update.id,
        MENDER_DEPLOYMENT_STATUS_REBOOTING, MERR_NONE);
    mender_reboot_expect(mender, MERR_UNKNOWN);

    sm.current_state = MENDER_STATE_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_REBOOT_ASYNC_REPORT);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ROLLBACK);
    assert_int_equal(sm.next_state_update, 0);

    /* successful reboot */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_report_update_status_expect(mender, sm.update.id,
        MENDER_DEPLOYMENT_STATUS_REBOOTING, MERR_NONE);
    mender_reboot_expect(mender, MERR_NONE);

    sm.current_state = MENDER_STATE_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_REBOOT_ASYNC_REPORT);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_DONE);
    assert_int_equal(sm.next_state_update, 0);

    /*
     * error while writing statedata
     * reboot will be performed regardless of failures to write update state data
     */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_UNKNOWN);
    mender_report_update_status_expect(mender, sm.update.id,
        MENDER_DEPLOYMENT_STATUS_REBOOTING, MERR_NONE);
    mender_reboot_expect(mender, MERR_NONE);

    sm.current_state = MENDER_STATE_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_REBOOT_ASYNC_REPORT);
    assert_int_equal(sm.last_error, MERR_NONE);
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_DONE);
    assert_int_equal(sm.next_state_update, 0);

    /* pretend update was aborted */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_report_update_status_expect(mender, sm.update.id,
        MENDER_DEPLOYMENT_STATUS_REBOOTING, MENDER_ERR_FATAL(MERR_DEPLOYMENT_ABORTED));

    sm.current_state = MENDER_STATE_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_REBOOT_ASYNC_REPORT);
    assert_int_equal(sm.last_error, MENDER_ERR_FATAL(MERR_DEPLOYMENT_ABORTED));
    assert_int_equal(sm.next_state_update, 0);

    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ROLLBACK);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_after_reboot(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    sm.current_state = MENDER_STATE_AFTER_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_VERIFY);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_rollback(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    expect_value(mender_swap_partitions_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_swap_partitions_test, MENDER_ERR_FATAL(MERR_UNKNOWN));
    sm.rollback_state.swap = true;
    sm.rollback_state.reboot = false;
    sm.current_state = MENDER_STATE_ROLLBACK;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);

    expect_value(mender_swap_partitions_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_swap_partitions_test, MERR_NONE);
    sm.current_state = MENDER_STATE_ROLLBACK;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_rollback_reboot(void **state __unused) {
    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_ROLLBACK_REBOOT;
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /* success */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_reboot_expect(mender, MERR_NONE);
    sm.current_state = MENDER_STATE_ROLLBACK_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_DONE);
    assert_int_equal(sm.next_state_update, 0);

    /* reboot failed */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    mender_reboot_expect(mender, MERR_UNKNOWN);
    sm.current_state = MENDER_STATE_ROLLBACK_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.last_error, MENDER_ERR_FATAL(MERR_UNKNOWN));

    /* storing state data failed */
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_UNKNOWN);
    mender_reboot_expect(mender, MERR_NONE);
    sm.current_state = MENDER_STATE_ROLLBACK_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_DONE);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_after_rollback_reboot(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    sm.current_state = MENDER_STATE_AFTER_ROLLBACK_REBOOT;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_UPDATE_ERROR);
    assert_int_equal(sm.next_state_update, 0);
    assert_int_equal(sm.last_error, MERR_UPDATE_FAILED);
}

static void test_state_final(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    sm.current_state = MENDER_STATE_DONE;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_STATEMACHINE_STOPPED);
    assert_int_equal(sm.current_state, MENDER_STATE_DONE);
    assert_int_equal(sm.next_state_update, MENDER_TIME_INFINITE);
}

static void test_state_data(void **state __unused) {
    memset(&sd, 0, sizeof(sd));
    sd.version = state_data_version;
    sd.state = MENDER_STATE_INIT;
    strcpy(sd.artifact_name, "fakeid");
    strcpy(sd.id, "00000000-0000-4000-0000-000000000000");
    sd.deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;

    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    assert_int_equal(store_state_data(store, &sd), MERR_NONE);

    memset(&rsd, 0, sizeof(rsd));
    mender_store_read_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    assert_int_equal(load_state_data(store, &rsd), MERR_NONE);
    assert_int_equal(memcmp(&sd, &rsd, sizeof(sd)), 0);

    sd.version = 999;
    mender_store_write_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    assert_int_equal(store_state_data(store, &sd), MERR_NONE);

    memset(&rsd, 0, sizeof(rsd));
    mender_store_read_all_expect(store, state_data_key, &sd, sizeof(sd), MERR_NONE);
    assert_int_equal(load_state_data(store, &rsd), MERR_UNSUPPORTED_STATE_DATA);
    assert_true(iszerobuf(&rsd, sizeof(rsd)) == 1);
    assert_int_equal(sd.version, 999);

    memset(&rsd, 0, sizeof(rsd));
    mender_store_read_all_expect(store, state_data_key, NULL, 0, MERR_NOT_FOUND);
    assert_int_equal(load_state_data(store, &rsd), MERR_NOT_FOUND);
    assert_true(iszerobuf(&rsd, sizeof(rsd)) == 1);
}

static void test_state_report_error(void **state __unused) {
    mender_statemachine_create(&sm, store, mender);
    will_return_always(mender_time_now_test, FAKE_TIME);

    /*
     * update succeeded, but we failed to report the status to the server,
     * rollback happens next
     */
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_SUCCESS;
    sm.current_state = MENDER_STATE_REPORT_STATUS_ERROR;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_ROLLBACK);
    assert_int_equal(sm.next_state_update, 0);

    /*
     * update failed and we failed to report that status to the server,
     * state data should be removed and we should go back to init
     */
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
    sm.current_state = MENDER_STATE_REPORT_STATUS_ERROR;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_IDLE);
    assert_int_equal(sm.next_state_update, 0);

    /*
     * update is already installed and we failed to report that status to
     * the server, state data should be removed and we should go back to
     * init
     */
    sm.deployment_status = MENDER_DEPLOYMENT_STATUS_ALREADY_INSTALLED;
    sm.current_state = MENDER_STATE_REPORT_STATUS_ERROR;
    assert_int_equal(mender_statemachine_run_once(&sm), MERR_NONE);
    assert_int_equal(sm.current_state, MENDER_STATE_IDLE);
    assert_int_equal(sm.next_state_update, 0);
}

static void test_state_max_sending_attempts(void **state __unused) {
    assert_int_equal(min_report_send_retries,
        max_sending_attempts(1, 0, min_report_send_retries));
    assert_int_equal(min_report_send_retries,
        max_sending_attempts(1, 1*60, min_report_send_retries));
    assert_int_equal(10, max_sending_attempts(5, 1, 3));
    assert_int_equal(min_report_send_retries,
        max_sending_attempts(1, 1, min_report_send_retries));
}

static const struct CMUnitTest tests_state[] = {
    cmocka_unit_test(test_state_error),
    cmocka_unit_test(test_state_update_error),
    cmocka_unit_test(test_state_update_report_status),
    cmocka_unit_test(test_state_idle),
    cmocka_unit_test(test_state_init),
    cmocka_unit_test(test_state_authorize),
    cmocka_unit_test(test_state_inventory_update),
    cmocka_unit_test(test_state_authorize_wait),
    cmocka_unit_test(test_state_update_verify),
    cmocka_unit_test(test_state_update_commit),
    cmocka_unit_test(test_state_update_check_wait),
    cmocka_unit_test(test_state_update_check),
    cmocka_unit_test(test_state_update_check_same_image),
    cmocka_unit_test(test_state_update_fetch),
    cmocka_unit_test(test_state_update_fetch_send_report_async),
    cmocka_unit_test(test_state_update_fetch_send_dofetch_async),
    cmocka_unit_test(test_state_update_fetch_retry),
    cmocka_unit_test(test_state_update_store),
    cmocka_unit_test(test_state_update_store_async_report),
    cmocka_unit_test(test_state_update_install),
    cmocka_unit_test(test_state_update_install_async_report),
    cmocka_unit_test(test_state_fetch_store_retry_wait),
    cmocka_unit_test(test_state_reboot),
    cmocka_unit_test(test_state_after_reboot),
    cmocka_unit_test(test_state_rollback),
    cmocka_unit_test(test_state_rollback_reboot),
    cmocka_unit_test(test_state_after_rollback_reboot),
    cmocka_unit_test(test_state_final),
    cmocka_unit_test(test_state_data),
    cmocka_unit_test(test_state_report_error),
    cmocka_unit_test(test_state_max_sending_attempts),
};

static int setup(void **state __unused) {
    memset(&sm, 0, sizeof(sm));
    memset(&update, 0, sizeof(update));
    memset(&sd, 0, sizeof(sd));
    memset(&rsd, 0, sizeof(rsd));

    mender_mocking_enabled = 1;
    mender_store_mocking_enabled = 1;
    mender_time_mocking_enabled = 1;
    return 0;
}

static int teardown(void **state __unused) {
    mender_mocking_enabled = 0;
    mender_store_mocking_enabled = 0;
    mender_time_mocking_enabled = 0;
    return 0;
}

int mender_test_run_state(void) {
    return cmocka_run_group_tests(tests_state, setup, teardown);
}
