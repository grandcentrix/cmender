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

#ifndef MENDER_STACK_H
#define MENDER_STACK_H

#include <mender/platform/types.h>
#include <mender/platform/config.h>

struct mender_stack {
    uint8_t *b;
    size_t size;
    size_t offset;
};

void mender_stack_create(struct mender_stack *stack, void *buf, size_t size);

void* mender_stack_take(struct mender_stack *stack, size_t n);
int mender_stack_give(struct mender_stack *stack, void *p, size_t n);

static inline size_t mender_stack_num_total(struct mender_stack *stack) {
    return stack->size;
}

static inline size_t mender_stack_num_free(struct mender_stack *stack) {
    size_t total = mender_stack_num_total(stack);

    if (total < stack->offset)
        return 0;

    return total - stack->offset;
}

static inline size_t mender_stack_num_used(struct mender_stack *stack) {
    return stack->offset;
}

static inline void* mender_stack_current(struct mender_stack *stack) {
    return &(stack->b[stack->offset]);
}

static inline void* mender_stack_base(struct mender_stack *stack) {
    return stack->b;
}

static inline int mender_stack_give_all(struct mender_stack *stack) {
    return mender_stack_give(stack, mender_stack_base(stack), mender_stack_num_used(stack));
}

#endif /* MENDER_STACK_H */
