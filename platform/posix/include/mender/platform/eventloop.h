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

#ifndef MENDER_PLATFORM_EVENTLOOP_H
#define MENDER_PLATFORM_EVENTLOOP_H

#include <mender/list.h>
#include <mender/time.h>

enum eventloop_flags {
    EVENTLOOP_FLAG_READ = 0x1,
    EVENTLOOP_FLAG_WRITE = 0x2,
    EVENTLOOP_FLAG_EXCEPT = 0x4
};

typedef void (*eventloop_cb_t)(void *ctx, int fd, enum eventloop_flags flags);
typedef void (*eventloop_cb_loop_t)(void *ctx);
typedef void (*eventloop_get_timeout_t)(void *ctx, mender_time_t *tnext);

struct eventloop_slot_fd {
    struct mender_list_node node;

    void *ctx;
    int fd;
    enum eventloop_flags flags;
    eventloop_cb_t cb;
};

struct eventloop_slot_loop {
    struct mender_list_node node;

    void *ctx;
    eventloop_cb_loop_t cb;
    eventloop_get_timeout_t get_timeout;
};

struct mender_platform_eventloop {
    struct mender_list_node list_fds;
    struct mender_list_node list_loop;
};

void mender_eventloop_create(struct mender_platform_eventloop *el);
void mender_eventloop_register_fd(struct mender_platform_eventloop *el, struct eventloop_slot_fd *slot_fd);
void mender_eventloop_remove_fd(struct mender_platform_eventloop *el, struct eventloop_slot_fd *slot_fd);
void mender_eventloop_register_loop_cb(struct mender_platform_eventloop *el, struct eventloop_slot_loop *slot_loop);
void mender_eventloop_remove_loop_cb(struct mender_platform_eventloop *el, struct eventloop_slot_loop *slot_loop);
int mender_eventloop_run(struct mender_platform_eventloop *el);

#endif /* MENDER_PLATFORM_EVENTLOOP_H */
