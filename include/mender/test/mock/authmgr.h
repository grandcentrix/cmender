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

#ifndef MENDER_TEST_MOCK_AUTHMGR_H
#define MENDER_TEST_MOCK_AUTHMGR_H

#include <mender/test/common.h>
#include <mender/platform/log.h>

extern int mender_authmgr_mocking_enabled;

__unused static inline mender_err_t mender_authmgr_remove_auth_token_mock(struct mender_authmgr *am) {
    if (!mender_authmgr_mocking_enabled)
        return mender_authmgr_remove_auth_token(am);

    function_called();

    check_expected_ptr(am);

    return mock_type(mender_err_t);
}

__unused static inline mender_err_t mender_authmgr_generate_authdata_mock(struct mender_authmgr *am,
        char *buf, size_t bufsz, size_t *pactual,
        const char **pdata, size_t *pdatalen,
        const char **psig, size_t *psiglen,
        const char **ptoken, size_t *ptokenlen) {
    if (!mender_authmgr_mocking_enabled)
        return mender_authmgr_generate_authdata_mock(am,
                buf, bufsz, pactual,
                pdata, pdatalen,
                psig, psiglen,
                ptoken, ptokenlen);

    function_called();

    check_expected_ptr(am);
    check_expected_ptr(buf);
    check_expected(bufsz);
    check_expected_ptr(pactual);
    check_expected_ptr(pdata);
    check_expected_ptr(pdatalen);
    check_expected_ptr(psig);
    check_expected_ptr(psiglen);
    check_expected_ptr(ptoken);
    check_expected_ptr(ptokenlen);

    return mock_type(mender_err_t);
}

__unused static inline mender_err_t mender_authmgr_set_token_mock(struct mender_authmgr *am,
        void *token, size_t tokensz) {
    (void)token; (void)tokensz;
    if (!mender_authmgr_mocking_enabled)
        return mender_authmgr_set_token(am, token, tokensz);

    function_called();

    check_expected_ptr(am);
    check_expected_ptr(token);
    check_expected_ptr(tokensz);

    return mock_type(mender_err_t);
}

__unused static inline mender_err_t mender_authmgr_get_token_mock(struct mender_authmgr *am,
        void *token, size_t maxtokensz, size_t *pactual) {
    (void)token; (void)maxtokensz; (void)pactual;
    if (!mender_authmgr_mocking_enabled)
        return mender_authmgr_get_token(am, token, maxtokensz, pactual);

    function_called();

    check_expected_ptr(am);

    return mock_type(mender_err_t);
}

__unused static inline int mender_authmgr_is_authorized_mock(struct mender_authmgr *am) {
    if (!mender_authmgr_mocking_enabled)
        return mender_authmgr_is_authorized(am);

    function_called();

    check_expected_ptr(am);

    return mock_type(int);
}

__unused static inline int mender_authmgr_has_key_mock(struct mender_authmgr *am) {
    if (!mender_authmgr_mocking_enabled)
        return mender_authmgr_has_key_mock(am);

    function_called();

    check_expected_ptr(am);

    return mock_type(int);
}

__unused static inline mender_err_t mender_authmgr_generate_key_mock(struct mender_authmgr *am) {
    if (!mender_authmgr_mocking_enabled)
        return mender_authmgr_generate_key_mock(am);

    function_called();

    check_expected_ptr(am);

    return mock_type(mender_err_t);
}

#define mender_authmgr_remove_auth_token mender_authmgr_remove_auth_token_mock
#define mender_authmgr_generate_authdata mender_authmgr_generate_authdata_mock
#define mender_authmgr_set_token mender_authmgr_set_token_mock
#define mender_authmgr_get_token mender_authmgr_get_token_mock
#define mender_authmgr_is_authorized mender_authmgr_is_authorized_mock
#define mender_authmgr_has_key mender_authmgr_has_key_mock
#define mender_authmgr_generate_key mender_authmgr_generate_key_mock

__unused static void expect_mender_authmgr_is_authorized(struct mender_authmgr *the_am, int ret) {
    expect_function_call(mender_authmgr_is_authorized_mock);
    expect_value(mender_authmgr_is_authorized_mock, am, cast_ptr_to_largest_integral_type(the_am));
    will_return(mender_authmgr_is_authorized_mock, ret);
}

__unused static void expect_mender_authmgr_has_key(struct mender_authmgr *the_am, int ret) {
    expect_function_call(mender_authmgr_has_key_mock);
    expect_value(mender_authmgr_has_key_mock, am, cast_ptr_to_largest_integral_type(the_am));
    will_return(mender_authmgr_has_key_mock, ret);
}

__unused static void expect_mender_authmgr_generate_key(struct mender_authmgr *the_am, mender_err_t ret) {
    expect_function_call(mender_authmgr_generate_key_mock);
    expect_value(mender_authmgr_generate_key_mock, am, cast_ptr_to_largest_integral_type(the_am));
    will_return(mender_authmgr_generate_key_mock, ret);
}

__unused static void expect_mender_authmgr_remove_auth_token(struct mender_authmgr *the_am, mender_err_t ret) {
    expect_function_call(mender_authmgr_remove_auth_token_mock);
    expect_value(mender_authmgr_remove_auth_token_mock, am, cast_ptr_to_largest_integral_type(the_am));
    will_return(mender_authmgr_remove_auth_token_mock, ret);
}

__unused static void expect_mender_authmgr_set_token(struct mender_authmgr *the_am,
        void *the_token, size_t the_tokensz, mender_err_t ret) {
    expect_function_call(mender_authmgr_set_token_mock);
    expect_value(mender_authmgr_set_token_mock, am, cast_ptr_to_largest_integral_type(the_am));
    expect_memory(mender_authmgr_set_token_mock, token, the_token, the_tokensz);
    expect_value(mender_authmgr_set_token_mock, tokensz, cast_ptr_to_largest_integral_type(the_tokensz));
    will_return(mender_authmgr_set_token_mock, ret);
}

#endif /* MENDER_TEST_MOCK_AUTHMGR_H */
