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

#ifndef MENDER_TEST_MOCK_INSTALLER_H
#define MENDER_TEST_MOCK_INSTALLER_H

#include <mender/test/common.h>
#include <mender/platform/log.h>

extern int mender_installer_mocking_enabled;

__unused static inline void mender_installer_create_mock(struct mender_installer *i, struct mender_device *device, struct mender_stack *stack, const char *device_type) {
    if (!mender_installer_mocking_enabled)
        mender_installer_create(i, device, stack, device_type);

    function_called();

    check_expected_ptr(i);
    check_expected_ptr(device);
    check_expected_ptr(stack);
    check_expected_ptr(device_type);
}

__unused static inline mender_err_t mender_installer_begin_mock(struct mender_installer *i, const char *expected_artifact_name) {
    if (!mender_installer_mocking_enabled)
        return mender_installer_begin(i, expected_artifact_name);

    function_called();

    check_expected_ptr(i);
    check_expected(expected_artifact_name);

    return mock_type(mender_err_t);
}

__unused static inline mender_err_t mender_installer_process_data_mock(struct mender_installer *i, const void *data, size_t length) {
    if (!mender_installer_mocking_enabled)
        return mender_installer_process_data(i, data, length);

    function_called();

    check_expected_ptr(i);
    check_expected(data);
    check_expected(length);

    return mock_type(mender_err_t);
}

__unused static inline mender_err_t mender_installer_finish_mock(struct mender_installer *i) {
    if (!mender_installer_mocking_enabled)
        return mender_installer_finish(i);

    function_called();

    check_expected_ptr(i);

    return mock_type(mender_err_t);
}

#define mender_installer_create mender_installer_create_mock
#define mender_installer_begin mender_installer_begin_mock
#define mender_installer_process_data mender_installer_process_data_mock
#define mender_installer_finish mender_installer_finish_mock

__unused static void expect_mender_installer_create(struct mender_installer *the_i, struct mender_device *the_device,
        struct mender_stack *the_stack, const char *the_device_type) {
    expect_function_call(mender_installer_create_mock);

    expect_value(mender_installer_create_mock, i, cast_ptr_to_largest_integral_type(the_i));
    expect_value(mender_installer_create_mock, device, cast_ptr_to_largest_integral_type(the_device));
    expect_value(mender_installer_create_mock, stack, cast_ptr_to_largest_integral_type(the_stack));
    expect_string(mender_installer_create_mock, device_type, the_device_type);
}

__unused static void expect_mender_installer_begin(struct mender_installer *the_i, const char *the_expected_artifact_name, mender_err_t ret) {
    expect_function_call(mender_installer_begin_mock);

    expect_value(mender_installer_begin_mock, i, cast_ptr_to_largest_integral_type(the_i));
    expect_string(mender_installer_begin_mock, expected_artifact_name, the_expected_artifact_name);

    will_return(mender_installer_begin_mock, ret);
}
__unused static void expect_mender_installer_process_data(struct mender_installer *the_i, const void *the_data, size_t the_length, mender_err_t ret) {
    expect_function_call(mender_installer_process_data_mock);

    expect_value(mender_installer_process_data_mock, i, cast_ptr_to_largest_integral_type(the_i));
    expect_memory(mender_installer_process_data_mock, data, the_data, the_length);
    expect_value(mender_installer_process_data_mock, length, the_length);

    will_return(mender_installer_process_data_mock, ret);
}

__unused static void expect_mender_installer_finish(struct mender_installer *the_i, mender_err_t ret) {
    expect_function_call(mender_installer_finish_mock);

    expect_value(mender_installer_finish_mock, i, cast_ptr_to_largest_integral_type(the_i));

    will_return(mender_installer_finish_mock, ret);
}

#endif /* MENDER_TEST_MOCK_INSTALLER_H */
