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

#ifndef MENDER_TEST_MOCK_KEYSTORE_H
#define MENDER_TEST_MOCK_KEYSTORE_H

#include <mender/test/common.h>

extern int mender_keystore_mocking_enabled;

static inline mender_err_t mender_keystore_load_test(struct mender_keystore *ks) {
    if (!mender_keystore_mocking_enabled) {
        return mender_keystore_load(ks);
    }

    check_expected_ptr(ks);
    return mock_type(mender_err_t);
}

static inline mender_err_t mender_keystore_save_test(struct mender_keystore *ks) {
    if (!mender_keystore_mocking_enabled) {
        return mender_keystore_save(ks);
    }

    check_expected_ptr(ks);
    return mock_type(mender_err_t);
}

static inline int mender_keystore_has_key_test(struct mender_keystore *ks) {
    if (!mender_keystore_mocking_enabled) {
        return mender_keystore_has_key(ks);
    }

    check_expected_ptr(ks);
    return mock_type(mender_err_t);
}

static inline mender_err_t mender_keystore_generate_test(struct mender_keystore *ks) {
    if (!mender_keystore_mocking_enabled) {
        return mender_keystore_generate(ks);
    }

    check_expected_ptr(ks);
    return mock_type(mender_err_t);
}

static inline mender_err_t mender_keystore_sign_test(struct mender_keystore *ks, const void *data, size_t datasize,
        char *sign, size_t maxsignsz, size_t *pactual) {
    void *src;
    size_t srclen;

    if (!mender_keystore_mocking_enabled) {
        return mender_keystore_sign(ks, data, datasize, sign, maxsignsz, pactual);
    }

    check_expected_ptr(ks);
    assert_non_null(data);
    assert_true(datasize > 0);

    src = mock_ptr_type(void*);
    srclen = mock_type(size_t);

    if (src && srclen) {
        assert_non_null(sign);
        assert_true(maxsignsz >= srclen);
        memcpy(sign, src, srclen);
    }

    if (pactual) {
        *pactual = srclen;
    }

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_keystore_get_public_pem_test(struct mender_keystore *ks, char *pem, size_t maxpemsize, size_t *pactual) {
    void *src;
    size_t srclen;

    if (!mender_keystore_mocking_enabled) {
        return mender_keystore_get_public_pem(ks, pem, maxpemsize, pactual);
    }

    check_expected_ptr(ks);

    src = mock_ptr_type(void*);
    srclen = mock_type(size_t);

    if (src && srclen) {
        assert_non_null(pem);
        assert_true(maxpemsize >= srclen);
        memcpy(pem, src, srclen);
    }

    if (pactual) {
        *pactual = srclen;
    }

    return mock_type(mender_err_t);
}

static inline mender_err_t mender_keystore_get_keytype_test(struct mender_keystore *ks, const char **ptype) {
    if (!mender_keystore_mocking_enabled) {
        return mender_keystore_get_keytype(ks, ptype);
    }

    check_expected_ptr(ks);

    assert_non_null(ptype);
    *ptype = mock_ptr_type(const char*);

    return mock_type(mender_err_t);
}

static inline void mender_keystore_load_expect(struct mender_keystore *ks, mender_err_t ret) {
    expect_value(mender_keystore_load_test, ks, cast_ptr_to_largest_integral_type(ks));
    will_return(mender_keystore_load_test, ret);
}

static inline void mender_keystore_sign_expect(struct mender_keystore *ks, const void *data, size_t datasize, mender_err_t ret) {
    expect_value(mender_keystore_sign_test, ks, cast_ptr_to_largest_integral_type(ks));
    will_return(mender_keystore_sign_test, cast_ptr_to_largest_integral_type(data));
    will_return(mender_keystore_sign_test, datasize);
    will_return(mender_keystore_sign_test, ret);
}

static inline void mender_keystore_get_public_pem_expect(struct mender_keystore *ks, const char *pem, size_t len, mender_err_t ret) {
    expect_value(mender_keystore_get_public_pem_test, ks, cast_ptr_to_largest_integral_type(ks));
    will_return(mender_keystore_get_public_pem_test, cast_ptr_to_largest_integral_type(pem));
    will_return(mender_keystore_get_public_pem_test, len);
    will_return(mender_keystore_get_public_pem_test, ret);
}

static inline void mender_keystore_get_keytype_expect(struct mender_keystore *ks, const char *type, mender_err_t ret) {
    expect_value(mender_keystore_get_keytype_test, ks, cast_ptr_to_largest_integral_type(ks));
    will_return(mender_keystore_get_keytype_test, type);
    will_return(mender_keystore_get_keytype_test, ret);
}

#define mender_keystore_load mender_keystore_load_test
#define mender_keystore_save mender_keystore_save_test
#define mender_keystore_has_key mender_keystore_has_key_test
#define mender_keystore_generate mender_keystore_generate_test
#define mender_keystore_sign mender_keystore_sign_test
#define mender_keystore_get_public_pem mender_keystore_get_public_pem_test
#define mender_keystore_get_keytype mender_keystore_get_keytype_test

#endif /* MENDER_TEST_MOCK_KEYSTORE_H */
