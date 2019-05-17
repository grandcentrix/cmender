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

#ifndef MENDER_INSTALLER_H
#define MENDER_INSTALLER_H

#include <mender/platform/types.h>
#include <mender/sha256.h>
#include <mender/error.h>
#include <mender/device.h>
#include <mender/http.h>
#include <mender/stack.h>
#include <jsmn.h>

enum mender_tar_state {
    MENDER_TAR_STATE_RECV_HDR = 0,
    MENDER_TAR_STATE_RECV_DATA
};

struct read_ctx {
    uint8_t *buf;
    size_t bufsz;
    size_t bufpos;
    size_t nskip;
};

struct mender_json_ctx {
    jsmn_parser parser;
    struct read_ctx readctx;
    struct mender_alignedstack_ctx tokens_ctx;
    jsmntok_t *tokens;
    size_t ntokens;
};

struct mender_readall_ctx {
    struct read_ctx readctx;
    jsmntok_t *tokens;
};

struct mender_tar_ctx {
    const struct mender_tar_cfg *cfg;
    size_t table_pos;

    enum mender_tar_state state;

    struct read_ctx readctx;

    // current file
    uint64_t filesize;
    uint64_t nrecv;
    uint8_t *sha;
    struct mender_sha256_context *sha_ctx;

    // type context for current file
    union {
        struct {
            struct mender_tar_ctx *subtar;
        } tar;

        struct mender_json_ctx json;

        struct mender_readall_ctx readall;
    } u;
};

struct mender_installer_state {
    // passed to begin
    const char *expected_artifact_name;

    struct mender_tar_ctx *root_tar_ctx;

    bool valid_files;
    bool valid_type_info;
    bool device_end_needed;
    bool successfull_install;

    uint8_t sha256_version_actual[32];
    uint8_t sha256_header[32];
    uint8_t sha256_rootfs[32];
    size_t root_tar_file_no;
};

struct mender_installer {
    // passed to create
    struct mender_device *device;
    struct mender_stack *stack;
    const char *device_type;

    // allocated in begin
    struct mender_installer_state *state;
};

void mender_installer_create(struct mender_installer *i, struct mender_device *device, struct mender_stack *stack, const char *device_type);
mender_err_t mender_installer_begin(struct mender_installer *i, const char *expected_artifact_name);
mender_err_t mender_installer_process_data(struct mender_installer *i, const void *data, size_t length);
mender_err_t mender_installer_finish(struct mender_installer *i);

#endif /* MENDER_INSTALLER_H */
