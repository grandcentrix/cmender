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

#ifndef MENDER_INSTALLER_HANDLERS_H
#define MENDER_INSTALLER_HANDLERS_H

#include <mender/platform/types.h>
#include <mender/error.h>
#include <mender/installer.h>

struct mender_tar_cfg {
    const struct mender_installer_file *files;
    size_t nfiles;
    size_t check_order_until;
};

extern const struct mender_tar_cfg root_tar_cfg;

enum mender_installer_file_type {
    MENDER_INSTALLER_FILE_TYPE_MANUAL,
    MENDER_INSTALLER_FILE_TYPE_READALL,
    MENDER_INSTALLER_FILE_TYPE_JSON,
    MENDER_INSTALLER_FILE_TYPE_TAR
};

struct mender_installer_file {
    /* filename, can be NULL to accept any file */
    const char *name;

    /*
     * if false, the parser aborts if the current name doesn't match.
     * XXX: The parser does NOT check if any files were missing. Do that yourself.
     */
    bool optional;

    /* if true, the sha256 checksum will be passed to 'end' */
    bool calculate_checksum;

    /* type, decides which member of the union should be used */
    enum mender_installer_file_type type;

    /* second filter after 'name' */
    mender_err_t (*wants)(struct mender_installer*, const char *name, bool *pwants);

    /* called after receiving the file header and doing all initializiation */
    mender_err_t (*start)(struct mender_installer*, const char *name, uint64_t size);

    /* called after receiving all file data. sha256 will be NULL if calculate_checksum is false */
    mender_err_t (*end)(struct mender_installer*, uint8_t *sha256);

    union {
        struct {
            mender_err_t (*recv)(struct mender_installer*, const void *data, size_t length);
        } manual;

        struct {
            mender_err_t (*recv)(struct mender_installer*, void *data, size_t length);
        } readall;

        struct {
            mender_err_t (*recv)(struct mender_installer*, char *buf, size_t bufsz, const jsmntok_t *tokens, size_t ntokens);
        } json;

        struct mender_tar_cfg tar;
    } u;
};


#define IS_JSON_STREQ(buf, tk, str) ((size_t)(tk->end-tk->start)==strlen(str) && !memcmp(buf+tk->start, str, strlen(str)))

#define UNSET_FLAG(i, f) i->flags &= ~(1<<f)
#define SET_FLAG(i, f) i->flags |= (1<<f)
#define GET_FLAG(i, f) ((i->flags&(1<<f))>>f)

#endif /* MENDER_INSTALLER_HANDLERS_H */
