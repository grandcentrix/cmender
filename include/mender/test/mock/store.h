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

#ifndef MENDER_TEST_MOCK_STORE_H
#define MENDER_TEST_MOCK_STORE_H

#include <mender/test/common.h>

extern int mender_store_mocking_enabled;

static inline int mender_store_has_test(struct mender_store *store, const char *key) {
    if (!mender_store_mocking_enabled)
        return mender_store_has(store, key);

    check_expected_ptr(store);
    check_expected_ptr(key);
    return mock_type(int);
}

static inline mender_err_t mender_store_read_all_test(struct mender_store *store,
        const char *key, void *data, size_t maxlen, size_t *pactual) 
{
    void *src;
    size_t srclen;

    if (!mender_store_mocking_enabled)
        return mender_store_read_all(store, key, data, maxlen, pactual);

    check_expected_ptr(store);
    check_expected_ptr(key);

    src = mock_ptr_type(void*);
    srclen = mock_type(size_t);

    if (src && srclen) {
        assert_non_null(data);
        assert_true(maxlen >= srclen);
        memcpy(data, src, srclen);
    }

    if (pactual) {
        *pactual = srclen;
    }

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_store_write_all_test(struct mender_store *store,
    const char *key, void *data, size_t len)
{
    void *dst;
    size_t dstlen;

    if (!mender_store_mocking_enabled)
        return mender_store_write_all(store, key, data, len);

    check_expected_ptr(store);
    check_expected_ptr(key);
    check_expected(len);
    dst = mock_ptr_type(void*);
    dstlen = mock_type(size_t);

    assert_non_null(data);

    if (dst && dstlen) {
        assert_int_equal(len, dstlen);
        assert_int_equal(memcmp(data, dst, len), 0);
    }

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_store_remove_test(struct mender_store *store, const char *key) {
    if (!mender_store_mocking_enabled)
        return mender_store_remove(store, key);

    check_expected_ptr(store);
    check_expected_ptr(key);
    return mock_type(mender_err_t);
}

static inline void mender_store_write_all_expect(struct mender_store *store,
    const char *key, void *data, size_t len, mender_err_t ret)
{
    expect_value(mender_store_write_all_test, store, cast_ptr_to_largest_integral_type(store));
    expect_string(mender_store_write_all_test, key, key);
    expect_value(mender_store_write_all_test, len, len);
    will_return(mender_store_write_all_test, cast_ptr_to_largest_integral_type(data));
    will_return(mender_store_write_all_test, len);
    will_return(mender_store_write_all_test, ret);
}

static inline void mender_store_read_all_expect(struct mender_store *store,
        const char *key, void *data, size_t len, mender_err_t ret) 
{
    expect_value(mender_store_read_all_test, store, cast_ptr_to_largest_integral_type(store));
    expect_string(mender_store_read_all_test, key, key);
    will_return(mender_store_read_all_test, cast_ptr_to_largest_integral_type(data));
    will_return(mender_store_read_all_test, len);
    will_return(mender_store_read_all_test, ret);
}

static inline void mender_store_remove_expect(struct mender_store *store, const char *key, mender_err_t ret) {
    expect_value(mender_store_remove_test, store, cast_ptr_to_largest_integral_type(store));
    expect_string(mender_store_remove_test, key, key);
    will_return(mender_store_remove_test, ret);
}

#define mender_store_has mender_store_has_test
#define mender_store_read_all mender_store_read_all_test
#define mender_store_write_all mender_store_write_all_test
#define mender_store_remove mender_store_remove_test

#endif /* MENDER_TEST_MOCK_STORE_H */
