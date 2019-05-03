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

#ifndef MENDER_TEST_MOCK_DEVICE_H
#define MENDER_TEST_MOCK_DEVICE_H

#include <mender/test/common.h>
#include <mender/platform/log.h>

extern int mender_device_mocking_enabled;

static inline mender_err_t mender_device_install_update_start_test(struct mender_device *dev, uint64_t size) {
    if (!mender_device_mocking_enabled)
        return mender_device_install_update_start(dev, size);

    function_called();

    check_expected_ptr(dev);
    check_expected(size);

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_device_install_update_process_data_test(struct mender_device *dev, const void *data, size_t len) {
    if (!mender_device_mocking_enabled)
        return mender_device_install_update_process_data(dev, data, len);

    if (len == 0) {
        LOGW("Warning: %s has been called with len 0, returning mock_type but don't checking expected values.", __FUNCTION__);
        return mock_type(mender_err_t);
    }

    check_expected_ptr(dev);
    check_expected_ptr(data);
    check_expected(len);

    function_called();

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_device_install_update_end_test(struct mender_device *dev) {
    if (!mender_device_mocking_enabled)
        return mender_device_install_update_end(dev);

    function_called();

    check_expected_ptr(dev);

    return mock_type(mender_err_t);
}

#define mender_device_install_update_start mender_device_install_update_start_test
#define mender_device_install_update_process_data mender_device_install_update_process_data_test
#define mender_device_install_update_end mender_device_install_update_end_test

#endif /* MENDER_TEST_MOCK_DEVICE_H */
