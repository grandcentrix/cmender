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

#include <mender/installer.h>
#include <mender/device.h>
#include <mender/platform/log.h>
#include <mender/internal/compiler.h>
#include <mender/utils.h>

#include <mender/installer_handlers.h>

#ifdef MENDER_ENABLE_TESTING
#include <mender/test/mock/device.h>
#endif

static bool match_headers_prefix(const char *fn) {
    return (!memcmp(fn, "headers/", strlen("headers/")) &&
            mender_isdigit(fn[8]) && mender_isdigit(fn[9]) && mender_isdigit(fn[10]) && mender_isdigit(fn[11]) &&
            fn[12] == '/'
        );
}

static bool match_headers_name(struct mender_installer *i __unused, const char *name, const char *suffix, bool *pwants) {
    if (match_headers_prefix(name)) {
        /* Prefix "headers/" is exactly 8 bytes long */
        /* At the moment, the only used bucket is 0 */
        if (atoi(name+8) == 0) {
            /* The prefix with "headers/", 4 digits and another '/' is 13 bytes long */
            if (!strcmp(name+13, suffix)) {
                *pwants = true;
                return MERR_NONE;
            }
        }
    }

    *pwants = false;
    return MERR_NONE;
}

static inline mender_err_t _mender_installer_json_skip(const jsmntok_t *tkn, size_t *skip) {
    size_t ntokens = 0;
    size_t toskip;

    tkn++;

    for (toskip = tkn->size; toskip > 0; toskip--) {
        const jsmntok_t *tk = tkn+ntokens;

        ntokens++;

        for (size_t i = 0; i < (size_t)tk->size; i++) {
            const jsmntok_t *tkk = tkn+(ntokens++);

            /* here could be some sort of recursion, but we just stop here and fail */
            if (tkk->type == JSMN_ARRAY || tkk->type == JSMN_OBJECT)
                return MERR_JSON_TYPE_ERROR;

            ntokens += tkk->size;
        }
    }

    *skip += ntokens;

    return MERR_NONE;
}

/*
 * version
 */
static mender_err_t mender_installer_version_recv(struct mender_installer *i __unused, char *buf, size_t bufsz __unused, const jsmntok_t *tokens, size_t ntokens)
{
    size_t cnt = 0;
    const jsmntok_t *format = NULL;
    const jsmntok_t *version = NULL;

    if (tokens[cnt++].type != JSMN_OBJECT)
        return MERR_JSON_TYPE_ERROR;

    while (cnt < ntokens) {
        const jsmntok_t *tk = &tokens[cnt++];
        const jsmntok_t *tv = &tokens[cnt++];

        if (tk->type != JSMN_STRING)
            return MERR_JSON_TYPE_ERROR;

        if (IS_JSON_STREQ(buf, tk, "format")) {
            if (format == NULL)
                format = tv;
            else
                return MERR_JSON_UNEXPECTED_KEY;
        }
        else if (IS_JSON_STREQ(buf, tk, "version")) {
            buf[tv->end] = 0;
            LOGD("Version: %s", buf+tv->start);

            if (version == NULL)
                version = tv;
            else
                return MERR_JSON_UNEXPECTED_KEY;
        }
        else {
            buf[tk->end] = 0;
            LOGE("Got unexpected key '%s'", buf+tk->start);
            return MERR_JSON_UNEXPECTED_KEY;
        }
    }

    if (format == NULL) {
        LOGE("Format not found.");
        return MERR_JSON_KEY_MISSING;
    }

    if (format->type != JSMN_STRING)
        return MERR_JSON_TYPE_ERROR;

    if (!IS_JSON_STREQ(buf, format, "mender")) {
        buf[format->end] = 0;
        LOGE("Unsupported update format '%s'", buf+format->start);
        return MERR_UNSUPPORTED;
    }

    if (version == NULL) {
        LOGE("Version not found.");
        return MERR_JSON_KEY_MISSING;
    }

    if (strcmp((const char*)buf+version->start, "2")) {
        LOGE("Only Version 2 is supported.");
        return MERR_UNSUPPORTED;
    }

    return MERR_NONE;
}

static mender_err_t mender_installer_version_end(struct mender_installer *i, uint8_t *sha256)
{
    memcpy(i->state->sha256_version_actual, sha256, 32);
    return MERR_NONE;
}

/*
 * manifest
 */
static mender_err_t mender_installer_manifest_recv(struct mender_installer *i, void *data, size_t length)
{
    char *buf = data;
    size_t n;
    uint8_t *sha256;

    const char *checksum_hex = data;
    const char *filename = NULL;
    for (n=0; n < length; n++) {
        if (buf[n] == ' ') {
            buf[n] = '\0';
            filename = &buf[n+1];
        }

        if (buf[n] == '\n') {
            buf[n] = '\0';

            if (!filename) {
                LOGE("filename missing");
                return MERR_INVALID_MANIFEST;
            }

            sha256 = mender_stack_take(i->stack, 32);
            if (!sha256) {
                LOGD("not enough stack space for sha256");
                return MERR_OUT_OF_RESOURCES;
            }

            if (mender_hex2bytes(checksum_hex, sha256, 32) != 64) {
                LOGE("checksum for %s is invalid: %s", filename, checksum_hex);
                return MERR_INVALID_MANIFEST;
            }

            if (!strcmp(filename, "version")) {
                if (memcmp(i->state->sha256_version_actual, sha256, 32)) {
                    LOGE("checksum for version doesn't match");
                    return MERR_CHECKSUM_WRONG;
                }
            }

            else if (!strcmp(filename, "header.tar")) {
                memcpy(i->state->sha256_header, sha256, 32);
            }

            else if (strstr(filename, "data/") == filename) {
                memcpy(i->state->sha256_rootfs, sha256, 32);
            }

            mender_stack_give(i->stack, sha256, 32);

            checksum_hex = &buf[n + 1];
            filename = NULL;
        }
    }

    return MERR_NONE;
}

/*
 * header.tar
 */
static mender_err_t mender_installer_header_end(struct mender_installer *i, uint8_t *sha256)
{
    if (!sha256) {
        LOGE("we didn't get a checksum");
        return MERR_IMPLEMENTATION_BUG;
    }

    if (memcmp(i->state->sha256_header, sha256, 32)) {
        LOGE("header checksum doesn't match");
        return MERR_CHECKSUM_WRONG;
    }

    if (!i->state->valid_files) {
        LOGE("never received 'files'");
        return MERR_MISSING_FILE;
    }

    if (!i->state->valid_type_info) {
        LOGE("never received 'type-info'");
        return MERR_MISSING_FILE;
    }

    return MERR_NONE;
}


/*
 * data/XXXX.tar/Y
 */
static mender_err_t mender_installer_data_start(struct mender_installer *i, const char *name __unused, uint64_t size)
{
    mender_err_t merr;

    merr = mender_device_install_update_start(i->device, size);
    if (merr) {
        LOGE("install_update_start failed");
        return merr;
    }

    i->state->device_end_needed = true;

    return MERR_NONE;
}

static mender_err_t mender_installer_data_end(struct mender_installer *i, uint8_t *sha256)
{
    mender_err_t merr;

    i->state->device_end_needed = false;

    merr = mender_device_install_update_end(i->device);
    if (merr) {
        LOGE("install_update_process_data failed");
        return merr;
    }

    if (!sha256) {
        LOGE("we didn't get a checksum");
        return MERR_IMPLEMENTATION_BUG;
    }

    if (memcmp(i->state->sha256_rootfs, sha256, 32)) {
        LOGE("data checksum doesn't match");
        return MERR_CHECKSUM_WRONG;
    }

    i->state->successfull_install = true;

    return MERR_NONE;
}

static mender_err_t mender_installer_data_recv(struct mender_installer *i, const void *data, size_t length)
{
    mender_err_t merr;

    merr = mender_device_install_update_process_data(i->device, data, length);
    if (merr) {
        LOGE("install_update_process_data failed");
        return merr;
    }

    return MERR_NONE;
}


/*
 * header-info
 */

static mender_err_t mender_installer_header_info_recv(struct mender_installer *i, char *buf, size_t bufsz __unused, const jsmntok_t *tokens, size_t ntokens)
{
    mender_err_t merr;
    size_t cnt = 0;
    int32_t device_type = -1;
    const jsmntok_t *artifact_name = NULL;
    char *artifact_name_s = NULL;

    if (tokens[cnt++].type != JSMN_OBJECT)
        return MERR_JSON_TYPE_ERROR;

    while (cnt < ntokens) {
        const jsmntok_t *tk = &tokens[cnt++];
        const jsmntok_t *tv = &tokens[cnt++];
        if (tk->type != JSMN_STRING)
            return MERR_JSON_TYPE_ERROR;

        if (IS_JSON_STREQ(buf, tk, "updates")) {
            if (tv->type != JSMN_ARRAY)
                return MERR_JSON_TYPE_ERROR;

            /*
             * As we do not want to store this information, we just skip it.
             * We'll get this information later anyways.
             */
            merr = _mender_installer_json_skip(tv, &cnt);
            if (merr != MERR_NONE)
                return merr;
        }
        else if (IS_JSON_STREQ(buf, tk, "device_types_compatible")) {
            if (tv->type != JSMN_ARRAY)
                return MERR_JSON_TYPE_ERROR;

            for (size_t n=0; n < (size_t)tv->size; n++) {
                const jsmntok_t *ntk = &tokens[cnt++];
                if (ntk->type != JSMN_STRING)
                    return MERR_JSON_TYPE_ERROR;

                mender_json_decode_str_inplace((char*)(buf+ntk->start), ntk->end-ntk->start, NULL);
                if (!strcmp((char*)(buf+ntk->start), i->device_type) && device_type < 0) {
                    device_type = n;
                }
            }

            if (device_type < 0) {
                LOGE("Artifact is not compatible!");
                return MERR_UNSUPPORTED;
            }
        }
        else if (IS_JSON_STREQ(buf, tk, "artifact_name")) {
            if (artifact_name == NULL)
                artifact_name = tv;
            else
                return MERR_JSON_UNEXPECTED_KEY;
        }
        else {
            buf[tk->end] = 0;
            LOGE("Got unexpected key '%s'", buf+tk->start);
            return MERR_JSON_UNEXPECTED_KEY;
        }
    }

    if (device_type < 0) {
        LOGE("device_type not found");
        return MERR_JSON_KEY_MISSING;
    }

    if (artifact_name == NULL) {
        LOGE("artifact_name not found");
        return MERR_JSON_KEY_MISSING;
    }

    if (i->state->expected_artifact_name == NULL) {
        LOGE("BUG");
        return MERR_IMPLEMENTATION_BUG;
    }

    if (artifact_name->type != JSMN_STRING)
        return MERR_JSON_TYPE_ERROR;

    artifact_name_s = buf+artifact_name->start;
    mender_json_decode_str_inplace(artifact_name_s, artifact_name->end-artifact_name->start, NULL);
    if (strcmp(artifact_name_s, i->state->expected_artifact_name)) {
        LOGE("artifact_name(%s) does not match the expected artifact_name(%s)", artifact_name_s, i->state->expected_artifact_name);
        return MERR_WRONG_ARTIFACT;
    }

    return MERR_NONE;
}


/*
 * headers/XXXX/files
 */

static mender_err_t mender_installer_header_files_wants(struct mender_installer *i, const char *name, bool *pwants) {
    return match_headers_name(i, name, "files", pwants);
}

static mender_err_t mender_installer_header_files_recv(struct mender_installer *i, char *buf, size_t bufsz __unused, const jsmntok_t *tokens, size_t ntokens)
{
    size_t cnt = 0;
    int32_t num_files = -1;

    if (i->state->valid_files) {
        LOGE("we already got 'files'");
        return MERR_UNSUPPORTED;
    }

    if (tokens[cnt++].type != JSMN_OBJECT)
        return MERR_JSON_TYPE_ERROR;

    while (cnt < ntokens) {
        const jsmntok_t *tk = &tokens[cnt++];
        const jsmntok_t *tv = &tokens[cnt++];

        if (tk->type != JSMN_STRING)
            return MERR_JSON_TYPE_ERROR;

        if (!IS_JSON_STREQ(buf, tk, "files")) {
            buf[tk->end] = 0;
            LOGE("Got unexpected key '%s'", buf+tk->start);
            return MERR_JSON_UNEXPECTED_KEY;
        }

        if (tv->type != JSMN_ARRAY)
            return MERR_JSON_TYPE_ERROR;

        num_files = tv->size;
        cnt += tv->size;
    }

    if (num_files < 0) {
        LOGE("Got no files");
        return MERR_JSON_KEY_MISSING;
    }

    if (num_files != 1) {
        LOGE("Can only install exactly one file for update, got %u", num_files);
        return MERR_UNSUPPORTED;
    }

    i->state->valid_files = true;
    return MERR_NONE;
}


/*
 * headers/XXXX/type-info
 */

static mender_err_t mender_installer_header_typeinfo_wants(struct mender_installer *i, const char *name, bool *pwants)
{
    return match_headers_name(i, name, "type-info", pwants);
}

static mender_err_t mender_installer_header_typeinfo_recv(struct mender_installer *i, char *buf, size_t bufsz __unused, const jsmntok_t *tokens, size_t ntokens)
{
    size_t cnt = 0;
    const jsmntok_t *type = NULL;

    if (i->state->valid_type_info) {
        LOGE("we already got 'type-info'");
        return MERR_UNSUPPORTED;
    }

    if (tokens[cnt++].type != JSMN_OBJECT)
        return MERR_JSON_TYPE_ERROR;

    while (cnt < ntokens) {
        const jsmntok_t *tk = &tokens[cnt++];
        const jsmntok_t *tv = &tokens[cnt++];

        if (tk->type != JSMN_STRING)
            return MERR_JSON_TYPE_ERROR;

        if (!IS_JSON_STREQ(buf, tk, "type")) {
            buf[tk->end] = 0;
            LOGE("Got unexpected key '%s'", buf+tk->start);
            return MERR_JSON_UNEXPECTED_KEY;
        }

        type = tv;
    }

    if (type == NULL) {
        LOGE("type not found");
        return MERR_JSON_KEY_MISSING;
    }

    if (type->type != JSMN_STRING)
        return MERR_JSON_TYPE_ERROR;

    if (!IS_JSON_STREQ(buf, type, "rootfs-image")) {
        buf[type->end] = 0;
        LOGE("Can only install updates of type 'rootfs-image', got '%s'", buf+type->start);
        return MERR_UNSUPPORTED;
    }

    i->state->valid_type_info = true;
    return MERR_NONE;
}

static const struct mender_installer_file mender_installer_header_file_records[] = {
    { 
        .name = "header-info",
        .optional = false,
        .type = MENDER_INSTALLER_FILE_TYPE_JSON,
        .u.json.recv = mender_installer_header_info_recv
    },

    /*
     * the following files are only optional because the order doesn't matter.
     * In that case, our parser doesn't support non-optional files and we have
     * to keep track of this ourselves.
     */

    /* files */
    { 
        .name = NULL,
        .optional = true,
        .type = MENDER_INSTALLER_FILE_TYPE_JSON,
        .wants = mender_installer_header_files_wants,
        .u.json.recv = mender_installer_header_files_recv
    },

    /* type-info */
    { 
        .name = NULL,
        .optional = true,
        .type = MENDER_INSTALLER_FILE_TYPE_JSON,
        .wants = mender_installer_header_typeinfo_wants,
        .u.json.recv = mender_installer_header_typeinfo_recv
    },
};

static const struct mender_installer_file mender_installer_data_file_records[] = {
    { 
        .name = NULL,
        .optional = false,
        .calculate_checksum = true,
        .type = MENDER_INSTALLER_FILE_TYPE_MANUAL,
        .start = mender_installer_data_start,
        .end = mender_installer_data_end,
        .u.manual.recv = mender_installer_data_recv,
    }
};

static const struct mender_installer_file mender_installer_file_records[] = {
    { 
        .name = "version",
        .optional = false,
        .calculate_checksum = true,
        .type = MENDER_INSTALLER_FILE_TYPE_JSON,
        .end = mender_installer_version_end,
        .u.json.recv = mender_installer_version_recv
    },

    { 
        .name = "manifest",
        .optional = false,
        .calculate_checksum = false,
        .type = MENDER_INSTALLER_FILE_TYPE_READALL,
        .u.readall.recv = mender_installer_manifest_recv
    },

    { 
        .name = "manifest.sig",
        .optional = true,
        .calculate_checksum = false,
        .type = MENDER_INSTALLER_FILE_TYPE_MANUAL,
    },

    { 
        .name = "header.tar",
        .optional = false,
        .calculate_checksum = true,
        .type = MENDER_INSTALLER_FILE_TYPE_TAR,
        .end = mender_installer_header_end,
        .u.tar.files = mender_installer_header_file_records,
        .u.tar.nfiles = ARRAY_SIZE(mender_installer_header_file_records),
        .u.tar.check_order_until = 1
    },

    { 
        .name = "data/0000.tar",
        .optional = false,
        .calculate_checksum = false,
        .type = MENDER_INSTALLER_FILE_TYPE_TAR,
        .u.tar.files = mender_installer_data_file_records,
        .u.tar.nfiles = ARRAY_SIZE(mender_installer_data_file_records),
        .u.tar.check_order_until = ARRAY_SIZE(mender_installer_data_file_records)
    }
};

const struct mender_tar_cfg root_tar_cfg = {
    .files = mender_installer_file_records,
    .nfiles = ARRAY_SIZE(mender_installer_file_records),
    .check_order_until = ARRAY_SIZE(mender_installer_file_records)
};
