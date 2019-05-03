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

static uint8_t stackbuf[4096];
static struct mender_stack stack;

static void test_stack_simple(void **state __unused) {
    void *b = mender_stack_take(&stack, 16);
    assert_ptr_equal(b, stackbuf);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 16);
    assert_int_equal(mender_stack_num_free(&stack), sizeof(stackbuf) - 16);
    assert_int_equal(mender_stack_num_used(&stack), 16);

    assert_int_equal(mender_stack_give(&stack, b, 16), 0);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf);
    assert_int_equal(mender_stack_num_free(&stack), sizeof(stackbuf));
    assert_int_equal(mender_stack_num_used(&stack), 0);
}

static void test_stack_giveall(void **state __unused) {
    void *b = mender_stack_take(&stack, 16);
    assert_ptr_equal(b, stackbuf);
    assert_int_equal(mender_stack_num_used(&stack), 16);

    assert_int_equal(mender_stack_give_all(&stack), 0);
    assert_int_equal(mender_stack_num_used(&stack), 0);
}

static void test_stack_unknownptr(void **state __unused) {
    void *b = mender_stack_take(&stack, 16);
    assert_ptr_equal(b, stackbuf);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 16);

    assert_int_equal(mender_stack_give(&stack, (void*)0xdeadbeef, 16), -1);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 16);
}

static void test_stack_givetoomuch(void **state __unused) {
    void *b = mender_stack_take(&stack, 16);
    assert_ptr_equal(b, stackbuf);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 16);

    assert_int_equal(mender_stack_give(&stack, b, 32), -1);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 16);
}

static void test_stack_giveoffsetptr(void **state __unused) {
    void *b = mender_stack_take(&stack, 16);
    assert_ptr_equal(b, stackbuf);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 16);

    assert_int_equal(mender_stack_give(&stack, b + 1, 16), -1);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 16);
}

static void test_stack_partialgive(void **state __unused) {
    void *b = mender_stack_take(&stack, 32);
    assert_ptr_equal(b, stackbuf);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 32);

    assert_int_equal(mender_stack_give(&stack, b + 16, 16), 0);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf + 16);

    assert_int_equal(mender_stack_give(&stack, b, 16), 0);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf);

    assert_int_equal(mender_stack_give(&stack, b, 0), 0);
    assert_ptr_equal(mender_stack_current(&stack), stackbuf);
}

static int setup(void **state __unused) {
    mender_stack_create(&stack, stackbuf, sizeof(stackbuf));
    assert_ptr_equal(mender_stack_base(&stack), stackbuf);
    assert_int_equal(mender_stack_num_total(&stack), sizeof(stackbuf));
    return 0;
}

static int teardown(void **state __unused) {
    memset(stackbuf, 0, sizeof(stackbuf));
    return 0;
}

#define stack_unit_test_setup(fn) cmocka_unit_test_setup_teardown(fn, setup, teardown)
static const struct CMUnitTest tests_stack[] = {
    stack_unit_test_setup(test_stack_simple),
    stack_unit_test_setup(test_stack_giveall),
    stack_unit_test_setup(test_stack_unknownptr),
    stack_unit_test_setup(test_stack_givetoomuch),
    stack_unit_test_setup(test_stack_giveoffsetptr),
    stack_unit_test_setup(test_stack_partialgive),
};

int mender_test_run_stack(void) {
    return cmocka_run_group_tests(tests_stack, NULL, NULL);
}
