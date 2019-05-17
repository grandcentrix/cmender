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

#define IS_ALIGNED(a, b) (!(((uintptr_t)(a)) & (((uintptr_t)(b))-1)))

static uint8_t stackbuf[4096] __attribute__ ((aligned (4)));
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

static void test_stack_aligned(void **state __unused) {
    void *b;
    struct mender_alignedstack_ctx ctx;

    // our stack must be aligned
    assert_true(IS_ALIGNED(stackbuf, 4));

    // make the offset unaligned
    b = mender_stack_take(&stack, 1);
    assert_ptr_equal(b, stackbuf);
    assert_true(IS_ALIGNED(b, 4));

    // just a self-check that the next take would return an unaligned buffer
    b = mender_stack_take(&stack, 1);
    assert_ptr_equal(b, stackbuf + 1);
    assert_false(IS_ALIGNED(b, 4));
    assert_int_equal(mender_stack_give(&stack, b, 1), 0);

    // the alignment offset must be substracted from the actual free space
    assert_int_equal(mender_alignedstack_num_free(&stack, 4), mender_stack_num_free(&stack) - 3);

    // take aligned memory
    b = mender_alignedstack_take(&ctx, &stack, 1, 4);
    assert_ptr_equal(b, stackbuf + 4);
    assert_true(IS_ALIGNED(b, 4));

    // take/give normal while we have an aligned buffer
    b = mender_stack_take(&stack, 32);
    assert_int_equal(b, stackbuf + 4 + 1);
    assert_int_equal(mender_stack_give(&stack, b, 32), 0);

    // give back aligned memory
    assert_int_equal(mender_alignedstack_give(&ctx, &stack), 0);
    assert_ptr_equal(stack.offset, 1);

    // take everything
    b = mender_alignedstack_take(&ctx, &stack, mender_alignedstack_num_free(&stack, 4), 4);
    assert_ptr_equal(b, stackbuf + 4);
    assert_true(IS_ALIGNED(b, 4));

    // and give it back
    assert_int_equal(mender_alignedstack_give(&ctx, &stack), 0);
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
    stack_unit_test_setup(test_stack_aligned),
};

int mender_test_run_stack(void) {
    return cmocka_run_group_tests(tests_stack, NULL, NULL);
}
