/*
 * Copyright (C) 2022 grandcentrix GmbH
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

#ifndef MENDER_TEST_MOCK_IDENTITY_DATA_H
#define MENDER_TEST_MOCK_IDENTITY_DATA_H

#include <mender/test/common.h>

extern int mender_identity_data_mocking_enabled;

static inline mender_err_t mender_identity_data_write_test(struct mender_identity_data *id, char *buf, size_t bufsz, size_t *pactual) {
    void *src;
    size_t srclen;

    if (!mender_identity_data_mocking_enabled) {
        return mender_identity_data_write(id, buf, bufsz, pactual);
    }

    check_expected_ptr(id);

    src = mock_ptr_type(void*);
    srclen = mock_type(size_t);

    if (src && srclen) {
        assert_non_null(buf);
        assert_true(bufsz >= srclen);
        memcpy(buf, src, srclen);
    }

    if (pactual) {
        *pactual = srclen;
    }

    return mock_type(mender_err_t);
}

static inline void mender_identity_data_write_expect(struct mender_identity_data *id, const char *data, size_t len, mender_err_t ret) {
    expect_value(mender_identity_data_write_test, id, cast_ptr_to_largest_integral_type(id));
    will_return(mender_identity_data_write_test, cast_ptr_to_largest_integral_type(data));
    will_return(mender_identity_data_write_test, len);
    will_return(mender_identity_data_write_test, ret);
}

#define mender_identity_data_write mender_identity_data_write_test

#endif /* MENDER_TEST_MOCK_IDENTITY_DATA_H */
