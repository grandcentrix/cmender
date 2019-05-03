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

#ifndef MENDER_TEST_MOCK_TIME_H
#define MENDER_TEST_MOCK_TIME_H

extern int mender_time_mocking_enabled;

static inline mender_time_t mender_time_now_test(void) {
    if (!mender_time_mocking_enabled)
        return mender_time_now();

    return mock_type(mender_time_t);
}

#define mender_time_now mender_time_now_test

#endif /* MENDER_TEST_MOCK_TIME_H */
