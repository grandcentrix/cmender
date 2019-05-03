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

#include <mender/platform/eventloop.h>
#include <mender/platform/types.h>
#include <mender/platform/log.h>
#include <mender/internal/list.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>

void mender_eventloop_create(struct mender_platform_eventloop *el) {
    mender_list_initialize(&el->list_fds);
    mender_list_initialize(&el->list_loop);
}

void mender_eventloop_register_fd(struct mender_platform_eventloop *el, struct eventloop_slot_fd *slot_fd) {
    mender_list_add_tail(&el->list_fds, &slot_fd->node);
}

void mender_eventloop_remove_fd(struct mender_platform_eventloop *el __unused, struct eventloop_slot_fd *slot_fd) {
    if (slot_fd->node.next && slot_fd->node.prev)
        mender_list_delete(&slot_fd->node);
}

void mender_eventloop_register_loop_cb(struct mender_platform_eventloop *el, struct eventloop_slot_loop *slot_loop) {
    mender_list_add_tail(&el->list_loop, &slot_loop->node);
}

void mender_eventloop_remove_loop_cb(struct mender_platform_eventloop *el __unused, struct eventloop_slot_loop *slot_loop) {
    if (slot_loop->node.next && slot_loop->node.prev)
        mender_list_delete(&slot_loop->node);
}

int mender_eventloop_run(struct mender_platform_eventloop *el) {
    int rc;
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    int maxfd;
    struct eventloop_slot_fd *slot_fd;
    struct eventloop_slot_fd *slot_fd_tmp;
    struct eventloop_slot_loop *slot_loop;
    struct eventloop_slot_loop *slot_loop_tmp;
    mender_time_t loop_next;

    for(;;) {
        struct timeval timeout;
        struct timeval *ptimeout = NULL;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        maxfd = -1;

        loop_next = MENDER_TIME_INFINITE;
        mender_list_for_every_entry_safe(&el->list_loop, slot_loop, slot_loop_tmp, struct eventloop_slot_loop, node) {
            mender_time_t next;

            if (!slot_loop->cb || !slot_loop->get_timeout)
                continue;

            next = MENDER_TIME_INFINITE;
            slot_loop->get_timeout(slot_loop->ctx, &next);

            if (next < loop_next)
                loop_next = next;
        }

        mender_list_for_every_entry(&el->list_fds, slot_fd, struct eventloop_slot_fd, node) {
            if (slot_fd->fd < 0)
                continue;

            if (slot_fd->flags & EVENTLOOP_FLAG_READ)
                FD_SET(slot_fd->fd, &readfds);
            if (slot_fd->flags & EVENTLOOP_FLAG_WRITE)
                FD_SET(slot_fd->fd, &writefds);
            if (slot_fd->flags & EVENTLOOP_FLAG_EXCEPT)
                FD_SET(slot_fd->fd, &exceptfds);

            if (slot_fd->fd > maxfd) {
                maxfd = slot_fd->fd;
            }
        }

        if (loop_next != MENDER_TIME_INFINITE) {
            mender_time_t now = mender_time_now();
            mender_time_t delta;
            if (loop_next > now) {
                delta = loop_next - now;
            } else {
                delta = 0;
            }
            ptimeout = &timeout;
            ptimeout->tv_sec = delta;
            ptimeout->tv_usec = 0;
        }

        if (maxfd == -1 && !ptimeout) {
            LOGW("eventloop is about to block forever");
        }

        rc = select(maxfd + 1, &readfds, &writefds, &exceptfds, ptimeout);
        if (rc == -1 && errno == EINTR) {
            continue;
        }
        if (rc < 0) {
            LOGE("select failed: %d %s", rc, strerror(errno));
            return -1;
        }

        mender_list_for_every_entry_safe(&el->list_fds, slot_fd, slot_fd_tmp, struct eventloop_slot_fd, node) {
            enum eventloop_flags flags = 0;

            if (slot_fd->fd < 0)
                continue;

            if (FD_ISSET(slot_fd->fd, &readfds))
                flags |= EVENTLOOP_FLAG_READ;
            if (FD_ISSET(slot_fd->fd, &writefds))
                flags |= EVENTLOOP_FLAG_WRITE;
            if (FD_ISSET(slot_fd->fd, &exceptfds))
                flags |= EVENTLOOP_FLAG_EXCEPT;

            if (flags) {
                slot_fd->cb(slot_fd->ctx, slot_fd->fd, flags);
            }
        }

        mender_list_for_every_entry_safe(&el->list_loop, slot_loop, slot_loop_tmp, struct eventloop_slot_loop, node) {
            if (!slot_loop->cb)
                continue;

            slot_loop->cb(slot_loop->ctx);
        }
    }

    return 0;
}
