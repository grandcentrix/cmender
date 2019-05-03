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
#include <mender/hexdump.h>

static void test_utils_isdigit(void **state __unused) {
    uint8_t n;
    size_t ntests = 0;

    for (n = 0; n < '0'; n++) {
        assert_int_equal(mender_isdigit(n), 0);
        ntests++;
    }

    for (; n <= '9'; n++) {
        assert_int_equal(mender_isdigit(n), 1);
        ntests++;
    }

    for (; n < 255; n++) {
        assert_int_equal(mender_isdigit(n), 0);
        ntests++;
    }

    assert_int_equal(mender_isdigit(255), 0);
    ntests++;

    // test our tests
    assert_int_equal(ntests, 256);
}

static void test_utils_isxdigit(void **state __unused) {
    uint8_t n;
    size_t ntests = 0;

    for (n = 0; n < '0'; n++) {
        assert_int_equal(mender_isxdigit(n), 0);
        ntests++;
    }

    for (; n <= '9'; n++) {
        assert_int_equal(mender_isxdigit(n), 1);
        ntests++;
    }

    for (; n < 'A'; n++) {
        assert_int_equal(mender_isxdigit(n), 0);
        ntests++;
    }

    for (; n <= 'F'; n++) {
        assert_int_equal(mender_isxdigit(n), 1);
        ntests++;
    }

    for (; n < 'a'; n++) {
        assert_int_equal(mender_isxdigit(n), 0);
        ntests++;
    }

    for (; n <= 'f'; n++) {
        assert_int_equal(mender_isxdigit(n), 1);
        ntests++;
    }

    for (; n < 255; n++) {
        assert_int_equal(mender_isxdigit(n), 0);
        ntests++;
    }

    assert_int_equal(mender_isxdigit(255), 0);
    ntests++;

    // test our tests
    assert_int_equal(ntests, 256);
}

struct json_test {
    const char *dec;
    const char *enc;
};

static struct json_test json_tests_ok[] = {
    {"simple", "simple"},
    {"\"simple\"", "\\\"simple\\\""},
    {"\\", "\\\\"},
    {"\"", "\\\""},
    {"\b", "\\b"},
    {"\f", "\\f"},
    {"\n", "\\n"},
    {"\r", "\\r"},
    {"\t", "\\t"},
    {"\x01", "\\u0001"},
};

static struct json_test json_tests_dec_fail[] = {
    {NULL, "\\u0"},
    {NULL, "\\u00"},
    {NULL, "\\u000"},
    {NULL, "\\uzzzz"},
    {NULL, "\\uffff"},
    {NULL, "\\x"},
    {NULL, "\\"},
};

static char json_test_buf[4096] __unused;

static void test_utils_json_encode(void **state __unused) {
    size_t i;
    mender_err_t merr;

    for (i = 0; i < ARRAY_SIZE(json_tests_ok); i++) {
        struct json_test *jt = &json_tests_ok[i];
        size_t dec_len = strlen(jt->dec);
        size_t enc_len = strlen(jt->enc);
        size_t outlen = 0;

        LOGD("dec:");
        mender_hexdump(jt->dec, dec_len);

        LOGD("enc:");
        mender_hexdump(jt->enc, enc_len);

        assert_true(dec_len + 1 <= sizeof(json_test_buf));
        memcpy(json_test_buf, jt->dec, dec_len + 1);

        merr = mender_json_encode_str_inplace(json_test_buf, sizeof(json_test_buf), &outlen);
        assert_int_equal(merr, MERR_NONE);
        LOGD("res:");
        mender_hexdump(json_test_buf, outlen);
        assert_int_equal(outlen, enc_len);
        assert_int_equal(memcmp(json_test_buf, jt->enc, enc_len + 1), 0);

        LOGD(" ");
    }
}

static void test_utils_json_decode(void **state __unused) {
    size_t i;
    mender_err_t merr;

    for (i = 0; i < ARRAY_SIZE(json_tests_ok); i++) {
        struct json_test *jt = &json_tests_ok[i];
        size_t dec_len = strlen(jt->dec);
        size_t enc_len = strlen(jt->enc);
        size_t outlen = 0;

        LOGD("dec:");
        mender_hexdump(jt->dec, dec_len);

        LOGD("enc:");
        mender_hexdump(jt->enc, enc_len);

        assert_true(enc_len + 1 <= sizeof(json_test_buf));
        memcpy(json_test_buf, jt->enc, enc_len + 1);

        merr = mender_json_decode_str_inplace(json_test_buf, enc_len, &outlen);
        assert_int_equal(merr, MERR_NONE);
        LOGD("res:");
        mender_hexdump(json_test_buf, outlen);
        assert_int_equal(outlen, dec_len + 1);
        assert_int_equal(memcmp(json_test_buf, jt->dec, dec_len + 1), 0);

        LOGD(" ");
    }

    for (i = 0; i < ARRAY_SIZE(json_tests_dec_fail); i++) {
        struct json_test *jt = &json_tests_dec_fail[i];
        size_t enc_len = strlen(jt->enc);
        size_t outlen = 0;

        LOGD("enc:");
        mender_hexdump(jt->enc, enc_len);

        assert_true(enc_len + 1 <= sizeof(json_test_buf));
        memcpy(json_test_buf, jt->enc, enc_len + 1);

        merr = mender_json_decode_str_inplace(json_test_buf, enc_len, &outlen);
        assert_int_equal(merr, MERR_INVALID_ARGUMENTS);

        LOGD(" ");
    }
}

static const struct CMUnitTest tests_utils[] = {
    cmocka_unit_test(test_utils_isdigit),
    cmocka_unit_test(test_utils_isxdigit),
    cmocka_unit_test(test_utils_json_encode),
    cmocka_unit_test(test_utils_json_decode),
};

int mender_test_run_utils(void) {
    return cmocka_run_group_tests(tests_utils, NULL, NULL);
}
