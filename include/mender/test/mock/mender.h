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

#ifndef MENDER_TEST_MOCK_MENDER_H
#define MENDER_TEST_MOCK_MENDER_H

#include <mender/test/common.h>

extern int mender_mocking_enabled;

static inline bool mender_is_authorized_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_is_authorized(mender);

    check_expected_ptr(mender);

    return mock_type(bool);
}

static inline void mender_authorize_test(struct mender *mender, mender_on_result_t cb, void *cbctx) {
    mender_err_t result;

    if (!mender_mocking_enabled) {
        mender_authorize(mender, cb, cbctx);
        return;
    }

    check_expected_ptr(mender);
    result = mock_type(mender_err_t);

    assert_non_null(cb);
    assert_non_null(cbctx);

    cb(cbctx, result);
}

static inline mender_err_t mender_get_current_artifact_name_test(struct mender *mender, const char **pname) {
    const char *name;

    if (!mender_mocking_enabled)
        return mender_get_current_artifact_name(mender, pname);

    check_expected_ptr(mender);
    name = mock_ptr_type(char*);

    assert_non_null(pname);
    *pname = name;

    return mock_type(mender_err_t);
}

static inline mender_duration_t mender_get_update_poll_interval_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_get_update_poll_interval(mender);

    check_expected_ptr(mender);

    return mock_type(mender_duration_t);
}

static inline mender_time_t mender_get_scheduled_update_time_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_get_scheduled_update_time(mender);

    check_expected_ptr(mender);

    return mock_type(mender_time_t);
}

static inline mender_duration_t mender_get_inventory_poll_interval_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_get_inventory_poll_interval(mender);

    check_expected_ptr(mender);

    return mock_type(mender_duration_t);
}

static inline mender_duration_t mender_get_retry_poll_interval_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_get_retry_poll_interval(mender);

    check_expected_ptr(mender);

    return mock_type(mender_duration_t);
}

static inline mender_err_t mender_has_upgrade_test(struct mender *mender, bool *phasupgrade) {
    bool hasupgrade;

    if (!mender_mocking_enabled)
        return mender_has_upgrade(mender, phasupgrade);

    check_expected_ptr(mender);
    hasupgrade = mock_type(bool);

    assert_non_null(phasupgrade);
    *phasupgrade = hasupgrade;

    return mock_type(mender_err_t);
}

static inline void mender_check_update_test(struct mender *mender,
        struct mender_update_response *ur, mender_on_result_t cb, void *cbctx)
{
    struct mender_update_response *ur_src;
    mender_err_t result;

    if (!mender_mocking_enabled) {
        mender_check_update(mender, ur, cb, cbctx);
        return;
    }

    check_expected_ptr(mender);
    ur_src = mock_ptr_type(struct mender_update_response*);
    result = mock_type(mender_err_t);

    assert_non_null(ur);
    assert_non_null(cb);
    assert_non_null(cbctx);

    if (ur_src) {
        memcpy(ur, ur_src, sizeof(*ur));
    }

    cb(cbctx, result);
}

static inline void mender_fetch_update_test(struct mender *mender, const char *url,
        char *artifact_name, mender_on_result_t cb, void *cbctx)
{
    mender_err_t result;

    if (!mender_mocking_enabled) {
        mender_fetch_update(mender, url, artifact_name, cb, cbctx);
        return;
    }

    check_expected_ptr(mender);
    check_expected(url);
    check_expected(artifact_name);
    result = mock_type(mender_err_t);

    assert_non_null(cb);
    assert_non_null(cbctx);

    cb(cbctx, result);
}

static inline void mender_report_update_status_test(struct mender *mender,
        const char *updateid, enum mender_deployment_status status,
        mender_on_result_t cb, void *cbctx)
{
    mender_err_t result;

    if (!mender_mocking_enabled) {
        mender_report_update_status(mender, updateid, status, cb, cbctx);
        return;
    }

    check_expected_ptr(mender);
    check_expected(updateid);
    check_expected(status);
    result = mock_type(mender_err_t);

    assert_non_null(cb);
    assert_non_null(cbctx);

    cb(cbctx, result);
}

static inline void mender_upload_log_test(struct mender *mender,
        const char *updateid, const char *logs,
        mender_on_result_t cb, void *cbctx)
{
    mender_err_t result;

    if (!mender_mocking_enabled) {
        mender_upload_log(mender, updateid, logs, cb, cbctx);
        return;
    }

    check_expected_ptr(mender);
    check_expected_ptr(updateid);
    check_expected_ptr(logs);
    result = mock_type(mender_err_t);

    assert_non_null(updateid);
    assert_non_null(cb);
    assert_non_null(cbctx);

    cb(cbctx, result);
}

static inline void mender_inventory_refresh_test(struct mender *mender, mender_on_result_t cb, void *cbctx) {
    mender_err_t result;

    if (!mender_mocking_enabled) {
        mender_inventory_refresh(mender, cb, cbctx);
        return;
    }

    check_expected_ptr(mender);
    result = mock_type(mender_err_t);

    assert_non_null(cb);
    assert_non_null(cbctx);

    cb(cbctx, result);
}

static inline mender_err_t mender_enable_updated_partition_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_enable_updated_partition(mender);

    check_expected_ptr(mender);

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_commit_update_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_commit_update(mender);

    check_expected_ptr(mender);

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_reboot_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_reboot(mender);

    check_expected_ptr(mender);

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_swap_partitions_test(struct mender *mender) {
    if (!mender_mocking_enabled)
        return mender_swap_partitions(mender);

    check_expected_ptr(mender);

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_has_update_test(struct mender *mender, bool *phasupdate) {
    bool hasupdate;

    if (!mender_mocking_enabled)
        return mender_has_update(mender, phasupdate);

    check_expected_ptr(mender);
    hasupdate = mock_type(bool);

    assert_non_null(phasupdate);

    *phasupdate = hasupdate;

    return mock_type(mender_err_t);
}

static inline void mender_report_update_status_expect(struct mender *mender,
        const char *updateid, enum mender_deployment_status status,
        mender_err_t ret)
{
    expect_value(mender_report_update_status_test, mender, cast_ptr_to_largest_integral_type(mender));
    expect_string(mender_report_update_status_test, updateid, updateid);
    expect_value(mender_report_update_status_test, status, status);
    will_return(mender_report_update_status_test, ret);
}

static inline void mender_reboot_expect(struct mender *mender, mender_err_t ret) {
    expect_value(mender_reboot_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_reboot_test, ret);
}

static inline void mender_upload_log_expect(struct mender *mender,
        const char *updateid, const char *logs,
        mender_err_t ret)
{
    expect_value(mender_upload_log_test, mender, cast_ptr_to_largest_integral_type(mender));
    expect_value(mender_upload_log_test, updateid, cast_ptr_to_largest_integral_type(updateid));
    expect_value(mender_upload_log_test, logs, cast_ptr_to_largest_integral_type(logs));
    will_return(mender_upload_log_test, ret);
}

static inline void mender_get_update_poll_interval_expect(struct mender *mender, mender_duration_t ret) {
    expect_value(mender_get_update_poll_interval_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_get_update_poll_interval_test, ret);
}

static inline void mender_get_scheduled_update_time_expect(struct mender *mender, mender_time_t ret) {
    expect_value(mender_get_scheduled_update_time_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_get_scheduled_update_time_test, ret);
}

static inline void mender_get_inventory_poll_interval_expect(struct mender *mender, mender_duration_t ret) {
    expect_value(mender_get_inventory_poll_interval_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_get_inventory_poll_interval_test, ret);
}

static inline void mender_get_retry_poll_interval_expect(struct mender *mender, mender_duration_t ret) {
    expect_value(mender_get_retry_poll_interval_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_get_retry_poll_interval_test, ret);
}

static inline void mender_is_authorized_expect(struct mender *mender, mender_duration_t ret) {
    expect_value(mender_is_authorized_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_is_authorized_test, ret);
}

static inline void mender_has_upgrade_expect(struct mender *mender, bool hasupgrade, mender_err_t ret) {
    expect_value(mender_has_upgrade_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_has_upgrade_test, hasupgrade);
    will_return(mender_has_upgrade_test, ret);
}

static inline void mender_authorize_expect(struct mender *mender, mender_err_t ret) {
    expect_value(mender_authorize_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_authorize_test, ret);
}

static inline void mender_inventory_refresh_expect(struct mender *mender, mender_err_t ret) {
    expect_value(mender_inventory_refresh_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_inventory_refresh_test, ret);
}

static inline void mender_get_current_artifact_name_expect(struct mender *mender, const char *name, mender_err_t ret) {
    expect_value(mender_get_current_artifact_name_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_get_current_artifact_name_test, name);
    will_return(mender_get_current_artifact_name_test, ret);
}

static inline void mender_commit_update_expect(struct mender *mender, mender_err_t ret) {
    expect_value(mender_commit_update_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_commit_update_test, ret);
}

static inline void mender_check_update_expect(struct mender *mender,
        struct mender_update_response *ur, mender_err_t ret)
{
    expect_value(mender_check_update_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_check_update_test, ur);
    will_return(mender_check_update_test, ret);
}

static inline void mender_fetch_update_expect(struct mender *mender, const char *url,
        char *artifact_name, mender_err_t ret)
{
    expect_value(mender_fetch_update_test, mender, cast_ptr_to_largest_integral_type(mender));
    expect_string(mender_fetch_update_test, url, url);
    expect_string(mender_fetch_update_test, artifact_name, artifact_name);
    will_return(mender_fetch_update_test, ret);
}

static inline void mender_enable_updated_partition_expect(struct mender *mender, mender_err_t ret) {
    expect_value(mender_enable_updated_partition_test, mender, cast_ptr_to_largest_integral_type(mender));
    will_return(mender_enable_updated_partition_test, ret);
}


#define mender_is_authorized mender_is_authorized_test
#define mender_authorize mender_authorize_test
#define mender_get_current_artifact_name mender_get_current_artifact_name_test
#define mender_get_update_poll_interval mender_get_update_poll_interval_test
#define mender_get_scheduled_update_time mender_get_scheduled_update_time_test
#define mender_get_inventory_poll_interval mender_get_inventory_poll_interval_test
#define mender_get_retry_poll_interval mender_get_retry_poll_interval_test
#define mender_has_upgrade mender_has_upgrade_test
#define mender_check_update mender_check_update_test
#define mender_fetch_update mender_fetch_update_test
#define mender_report_update_status mender_report_update_status_test
#define mender_upload_log mender_upload_log_test
#define mender_inventory_refresh mender_inventory_refresh_test
#define mender_enable_updated_partition mender_enable_updated_partition_test
#define mender_commit_update mender_commit_update_test
#define mender_reboot mender_reboot_test
#define mender_swap_partitions mender_swap_partitions_test
#define mender_has_update mender_has_update_test

#endif /* MENDER_TEST_MOCK_MENDER_H */
