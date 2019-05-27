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

#include <mender/platform/types.h>
#include <mender/test/common.h>
#include <mender/platform/log.h>

int mender_run_all_tests(void) {
    int ret = 0;
    int rc;

    rc = mender_test_run_state();
    if (rc)
        ret = -1;

    rc = mender_test_run_installer();
    if (rc)
        ret = -1;

    rc = mender_test_run_stack();
    if (rc)
        ret = -1;

    rc = mender_test_run_utils();
    if (rc)
        ret = -1;

    rc = mender_test_run_mender();
    if (rc)
        ret = -1;

    if (ret) {
        LOGE("SOME TESTS FAILED");
    }
    else {
        LOGI("ALL TESTS PASSED");
    }

    return ret;
}
