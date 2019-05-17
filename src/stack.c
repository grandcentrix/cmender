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

#include <mender/stack.h>
#include <mender/platform/log.h>
#include <mender/internal/compiler.h>

void mender_stack_create(struct mender_stack *stack, void *buf, size_t size) {
    memset(stack, 0, sizeof(*stack));
    stack->b = buf;
    stack->size = size;
    stack->offset = 0;
}

void* mender_stack_take(struct mender_stack *stack, size_t n) {
    void *p;

    if (n > mender_stack_num_free(stack)) {
        LOGE("OOM: have:%zu need:%zu", mender_stack_num_free(stack), n);
        return NULL;
    }

    p = &stack->b[stack->offset];
    stack->offset += n;

    return p;
}

int mender_stack_give(struct mender_stack *stack, void *p, size_t n) {
    if (p < (void*)stack->b || p > (void*)stack->b + stack->size) {
        LOGE("pointer is not from mender_stack");
        return -1;
    }

    if (n > stack->offset) {
        LOGE("giving more to mender_stack than was ever taken current=%zu got=%zu", stack->offset, n);
        return -1;
    }

    if (mender_stack_current(stack) - n != p) {
        LOGE("supplied bad mender_stack pointer. expected=%zu got=%zu", p - mender_stack_base(stack), stack->offset);
        return -1;
    }

    stack->offset -= n;

    return 0;
}

static inline size_t mender_alignedstack_calc_offset(struct mender_stack *stack, size_t align) {
    return ROUNDUP(stack->offset, align) - stack->offset;
}

void* mender_alignedstack_take(struct mender_alignedstack_ctx *ctx, struct mender_stack *stack, size_t n, size_t align) {
    size_t offset;
    size_t n_actual;
    void *mem;

    offset = mender_alignedstack_calc_offset(stack, align);
    n_actual = n + offset;

    mem = mender_stack_take(stack, n_actual);
    if (!mem)
        return NULL;

    ctx->mem = mem;
    ctx->n = n_actual;

    return mem + offset;
}

size_t mender_alignedstack_num_free(struct mender_stack *stack, size_t align) {
    return mender_stack_num_free(stack) - mender_alignedstack_calc_offset(stack, align);
}

int mender_alignedstack_give(struct mender_alignedstack_ctx *ctx, struct mender_stack *stack) {
    return mender_stack_give(stack, ctx->mem, ctx->n);
}

#ifdef MENDER_ENABLE_TESTING
#include "../tests/stack.c"
#endif
