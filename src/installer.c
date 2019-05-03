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

struct tar_hdr_raw {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];

/*
    we're not using any of these and removing them decreases the buffer size needed
    char mtime[12];
    char checksum[8];
    char typeflag[1];
    char linkname[100];
*/
} __packed;
#define TAR_HDR_SKIPLEN (512 - sizeof(struct tar_hdr_raw))

static mender_err_t handle_skip(struct read_ctx *ctx, const uint8_t **pdata, size_t *plength)
{
    if (ctx->nskip) {
        size_t toskip = MIN(ctx->nskip, *plength);
        *pdata += toskip;
        *plength -= toskip;
        ctx->nskip -= toskip;
    }

    return MERR_NONE;
}

static mender_err_t read_until(struct read_ctx *ctx, const uint8_t **pdata, size_t *plength,
        size_t until, int *pcomplete)
{
    if (ctx->bufpos >= until) {
        *pcomplete = 1;
        return MERR_NONE;
    }

    if (ctx->nskip) {
        return MERR_INVALID_STATE;
    }

    if (*plength) {
        size_t tocopy = MIN(until - ctx->bufpos, *plength);
        if (ctx->bufpos + tocopy > ctx->bufsz)
            return MERR_BUFFER_TOO_SMALL;

        memcpy(&ctx->buf[ctx->bufpos], *pdata, tocopy);
        ctx->bufpos += tocopy;
        *pdata += tocopy;
        *plength -= tocopy;
    }

    if (ctx->bufpos < until) {
        *pcomplete = 0;
        return MERR_NONE;
    }

    *pcomplete = 1;
    return MERR_NONE;
}

void mender_installer_create(struct mender_installer *i, struct mender_device *device, struct mender_stack *stack, const char *device_type) {
    memset(i, 0, sizeof(*i));
    i->device = device;
    i->stack = stack;
    i->device_type = device_type;
}

static struct mender_tar_ctx* alloc_tar_ctx(struct mender_stack *stack, const struct mender_tar_cfg *cfg)
{
    struct mender_tar_ctx *ctx;

    ctx = mender_stack_take(stack, sizeof(*ctx));
    if (!ctx) {
        LOGD("not enough stack space for tar ctx");
        return NULL;
    }
    memset(ctx, 0, sizeof(*ctx));

    ctx->cfg = cfg;
    ctx->table_pos = 0;
    ctx->filesize = 0;
    ctx->state = MENDER_TAR_STATE_RECV_HDR;

    /* alloc readctx for tar hdr */
    ctx->readctx.bufsz = sizeof(struct tar_hdr_raw);
    ctx->readctx.buf = mender_stack_take(stack, ctx->readctx.bufsz);
    if (!ctx->readctx.buf) {
        LOGD("not enough stack space for read ctx");
        return NULL;
    }

    return ctx;
}

static void free_tar_ctx(struct mender_stack *stack, struct mender_tar_ctx *ctx) {
    if (!ctx)
        return;

    /* XXX: we can't free the union since we don't know the current file type */

    if (ctx->readctx.buf)
        mender_stack_give(stack, ctx->readctx.buf, ctx->readctx.bufsz);

    mender_stack_give(stack, ctx, sizeof(*ctx));
}

mender_err_t mender_installer_begin(struct mender_installer *i, const char *expected_artifact_name) {
    LOGI("begin");

    i->state = mender_stack_take(i->stack, sizeof(*(i->state)));
    if (!i->state) {
        LOGD("not enough stack space for state");
        return MERR_OUT_OF_RESOURCES;
    }
    memset(i->state, 0, sizeof(*(i->state)));

    i->state->expected_artifact_name = expected_artifact_name;
    i->state->root_tar_file_no = 0;
    i->state->successfull_install = false;

    /* alloc root tar ctx */
    i->state->root_tar_ctx = alloc_tar_ctx(i->stack, &root_tar_cfg);
    if (!i->state->root_tar_ctx) {
        LOGD("not enough stack space for tar ctx");
        return MERR_OUT_OF_RESOURCES;
    }

    return MERR_NONE;
}

static mender_err_t mender_installer_process_data_json(struct mender_installer *i, const struct mender_installer_file *file, struct mender_json_ctx *ctx, const void *_data, size_t length) {
    const uint8_t *data = (const uint8_t *)_data;
    mender_err_t merr;
    int read_complete;
    int res;

    merr = read_until(&ctx->readctx, &data, &length, ctx->readctx.bufsz, &read_complete);
    if (merr || !read_complete)
        return merr;

    jsmn_init(&ctx->parser);

    res = jsmn_parse(&ctx->parser, (char *)ctx->readctx.buf, ctx->readctx.bufsz, ctx->tokens, ctx->ntokens);
    if (res < 0) {
        switch(res) {
            case JSMN_ERROR_INVAL:
                LOGD("JSON File is corrupted");
                return MERR_JSON_INVALID;
            case JSMN_ERROR_NOMEM:
                LOGD("JSON File is too big, not enough tokens");
                return MERR_OUT_OF_RESOURCES;
            case JSMN_ERROR_PART:
                LOGD("JSON File is partial");
                return MERR_JSON_PARTIAL;
        }
        return MERR_UNKNOWN;
    }

    if (!file->u.json.recv)
        return MERR_NONE;

    return file->u.json.recv(i, (char*)ctx->readctx.buf, ctx->readctx.bufsz, ctx->tokens, (size_t)res);
}

static mender_err_t mender_installer_process_data_readall(struct mender_installer *i, const struct mender_installer_file *file, struct mender_readall_ctx *ctx, const void *_data, size_t length) {
    const uint8_t *data = (const uint8_t *)_data;
    mender_err_t merr;
    int read_complete;

    merr = read_until(&ctx->readctx, &data, &length, ctx->readctx.bufsz - 1, &read_complete);
    if (merr || !read_complete)
        return merr;

    ctx->readctx.buf[ctx->readctx.bufsz - 1] = '\0';

    return file->u.readall.recv(i, ctx->readctx.buf, ctx->readctx.bufsz - 1);
}

static mender_err_t mender_installer_process_data_tar(struct mender_installer *i, struct mender_tar_ctx *ctx, const void *_data, size_t length) {
    const uint8_t *data = (const uint8_t *)_data;
    const struct mender_tar_cfg *cfg = ctx->cfg;
    struct read_ctx *readctx = &ctx->readctx;
    mender_err_t merr;
    struct tar_hdr_raw *hdr;
    uint64_t size;
    int read_complete;

    while (length) {
        merr = handle_skip(readctx, &data, &length);
        if (merr || readctx->nskip)
            return merr;

        switch (ctx->state) {
            case MENDER_TAR_STATE_RECV_HDR: {
                merr = read_until(readctx, &data, &length, sizeof(struct tar_hdr_raw), &read_complete);
                if (merr || !read_complete)
                    return merr;

                hdr = (void*)readctx->buf;
                hdr->name[sizeof(hdr->name) - 1] = '\0';

                size = (uint64_t) strtoull(hdr->size, NULL, 8);

                /* end of tar */
                if (strlen(hdr->name) == 0 && size == 0) {
                    readctx->nskip = TAR_HDR_SKIPLEN;
                    readctx->bufpos = 0;
                    continue;
                }

                /*
                 * if we don't care about order, everything else is implicitely optional
                 * so we'll just walk the whole table every single time
                 */
                if (ctx->table_pos > cfg->check_order_until)
                    ctx->table_pos = cfg->check_order_until;

                if (ctx->table_pos == cfg->nfiles) {
                    LOGE("unexpected file '%s' after successful table walk", hdr->name);
                    return MERR_INVALID_STATE;
                }

                while (ctx->table_pos < cfg->nfiles) {
                    const struct mender_installer_file *file = &cfg->files[ctx->table_pos];
                    bool wants = false;

                    /* the filename has to match if it's not NULL */
                    if (!file->name || !strcmp(hdr->name, file->name)) {
                        wants = true;
                    }

                    /* a 'wants'-callback may override that decision */
                    if (wants && file->wants) {
                        wants = false;
                        merr = file->wants(i, hdr->name, &wants);
                        if (merr) {
                            LOGE("wants failed");
                            return merr;
                        }
                    }

                    if (wants) {
                        if (file->calculate_checksum) {
                            ctx->sha = mender_stack_take(i->stack, 32);
                            if (!ctx->sha) {
                                LOGD("not enough stack space for sha");
                                return MERR_OUT_OF_RESOURCES;
                            }

                            ctx->sha_ctx = mender_stack_take(i->stack, sizeof((*ctx->sha_ctx)));
                            if (!ctx->sha_ctx) {
                                LOGD("not enough stack space for sha_ctx");
                                return MERR_OUT_OF_RESOURCES;
                            }

                            mender_sha256_begin(ctx->sha_ctx);
                        }

                        /* prepare for receiving data */
                        memset(&ctx->u, 0, sizeof(ctx->u));
                        switch (file->type) {
                            case MENDER_INSTALLER_FILE_TYPE_MANUAL:
                                /* nothing to do because we just forward all data to the callback */
                                break;

                            case MENDER_INSTALLER_FILE_TYPE_READALL:
                                ctx->u.readall.readctx.bufsz = size + 1;
                                ctx->u.readall.readctx.buf = mender_stack_take(i->stack, ctx->u.readall.readctx.bufsz);
                                if (!ctx->u.readall.readctx.buf) {
                                    LOGD("not enough stack space for readall buffer");
                                    return MERR_OUT_OF_RESOURCES;
                                }
                                break;

                            case MENDER_INSTALLER_FILE_TYPE_JSON:
                                ctx->u.json.readctx.bufsz = size;
                                ctx->u.json.readctx.buf = mender_stack_take(i->stack, ctx->u.json.readctx.bufsz);
                                if (!ctx->u.json.readctx.buf) {
                                    LOGD("not enough stack space for json buffer");
                                    return MERR_OUT_OF_RESOURCES;
                                }

                                ctx->u.json.ntokens = mender_stack_num_free(i->stack)/sizeof(jsmntok_t);
                                ctx->u.json.tokens = mender_stack_take(i->stack, ctx->u.json.ntokens * sizeof(jsmntok_t));
                                if (!ctx->u.json.tokens) {
                                    LOGD("not enough stack space for json tokens");
                                    return MERR_OUT_OF_RESOURCES;
                                }

                                break;

                            case MENDER_INSTALLER_FILE_TYPE_TAR:
                                ctx->u.tar.subtar = alloc_tar_ctx(i->stack, &file->u.tar);
                                if (!i->state->root_tar_ctx) {
                                    LOGD("not enough stack space for tar ctx");
                                    return MERR_OUT_OF_RESOURCES;
                                }
                                break;

                            default:
                                LOGE("invalid filetype '%d'", file->type);
                                return MERR_INVALID_STATE;
                        }

                        if (file->start) {
                            merr = file->start(i, hdr->name, size);
                            if (merr) {
                                LOGE("starting file '%s' failed", hdr->name);
                                return merr;
                            }
                        }

                        ctx->filesize = size;
                        ctx->state = MENDER_TAR_STATE_RECV_DATA;
                        ctx->nrecv = 0;

                        readctx->nskip = TAR_HDR_SKIPLEN;
                        readctx->bufpos = 0;
                        break;
                    }
                    else if (file->optional) {
                        ctx->table_pos++;
                    }
                    else if (ctx->table_pos >= cfg->check_order_until) {
                        LOGW("non-optional files aren't supported when ignoring order. skipping '%s' anyway. current=%s", file->name?:"<null>", hdr->name);
                        ctx->table_pos++;
                    }
                    else {
                        LOGE("non-optional file '%s' missing", file->name);
                        return MERR_INVALID_STATE;
                    }
                }

                if (ctx->state == MENDER_TAR_STATE_RECV_HDR) {
                    LOGD("skip file %s", hdr->name);
                    readctx->nskip = TAR_HDR_SKIPLEN + ROUNDUP(size, 512);
                    readctx->bufpos = 0;
                }

                break;
            }

            case MENDER_TAR_STATE_RECV_DATA: {
                const struct mender_installer_file *file = &cfg->files[ctx->table_pos];
                uint64_t torecv = MIN(length, ctx->filesize - ctx->nrecv);

                /* process received data */
                switch (file->type) {
                    case MENDER_INSTALLER_FILE_TYPE_MANUAL:
                        if (file->u.manual.recv)
                            file->u.manual.recv(i, data, torecv);
                        break;

                    case MENDER_INSTALLER_FILE_TYPE_READALL:
                        merr = mender_installer_process_data_readall(i, file, &ctx->u.readall, data, torecv);
                        if (merr)
                            return merr;
                        break;

                    case MENDER_INSTALLER_FILE_TYPE_JSON:
                        merr = mender_installer_process_data_json(i, file, &ctx->u.json, data, torecv);
                        if (merr)
                            return merr;
                        break;

                    case MENDER_INSTALLER_FILE_TYPE_TAR:
                        merr = mender_installer_process_data_tar(i, ctx->u.tar.subtar, data, torecv);
                        if (merr)
                            return merr;
                        break;

                    default:
                        LOGE("invalid filetype '%d'", file->type);
                        return MERR_INVALID_STATE;
                }

                if (file->calculate_checksum) {
                    mender_sha256_process(ctx->sha_ctx, data, torecv);
                }

                ctx->nrecv += torecv;
                data += torecv;
                length -= torecv;

                /* we're done receiving the file */
                if (ctx->nrecv >= ctx->filesize) {
                    /* if this happens we have to blame ourselves */
                    if (ctx->nrecv > ctx->filesize) {
                        LOGE("BUG");
                        return MERR_IMPLEMENTATION_BUG;
                    }

                    if (file->calculate_checksum) {
                        mender_sha256_end(ctx->sha_ctx, ctx->sha);
                    }

                    if (file->end) {
                        merr = file->end(i, ctx->sha);
                        if (merr) {
                            LOGE("ending file '%s' failed", file->name?:"<null>");
                            return merr;
                        }
                    }

                    /* cleanup after receiving data */
                    switch (file->type) {
                        case MENDER_INSTALLER_FILE_TYPE_MANUAL:
                            /* nothing to do because we didn't do any initialization for this */
                            break;

                        case MENDER_INSTALLER_FILE_TYPE_READALL:
                            mender_stack_give(i->stack, ctx->u.readall.readctx.buf, ctx->u.readall.readctx.bufsz);
                            break;

                        case MENDER_INSTALLER_FILE_TYPE_JSON:
                            mender_stack_give(i->stack, ctx->u.json.tokens, ctx->u.json.ntokens * sizeof(jsmntok_t));
                            mender_stack_give(i->stack, ctx->u.json.readctx.buf, ctx->u.json.readctx.bufsz);
                            break;

                        case MENDER_INSTALLER_FILE_TYPE_TAR:
                            free_tar_ctx(i->stack, ctx->u.tar.subtar);
                            ctx->u.tar.subtar = NULL;
                            break;

                        default:
                            LOGE("invalid filetype '%d'", file->type);
                            return MERR_INVALID_STATE;
                    }

                    if (file->calculate_checksum) {
                        mender_stack_give(i->stack, ctx->sha_ctx, sizeof(*(ctx->sha_ctx)));
                        mender_stack_give(i->stack, ctx->sha, 32);
                    }

                    readctx->nskip += (size_t)(ROUNDUP(ctx->filesize, 512) - ctx->filesize);
                    readctx->bufpos = 0;

                    ctx->filesize = 0;
                    ctx->nrecv = 0;

                    ctx->state = MENDER_TAR_STATE_RECV_HDR;
                    if (file->name)
                        ctx->table_pos++;
                }

                break;
            }
        }
    }

    return MERR_NONE;
}

mender_err_t mender_installer_process_data(struct mender_installer *i, const void *data, size_t length) {
    mender_err_t merr;

    merr = mender_installer_process_data_tar(i, i->state->root_tar_ctx, data, length);

    if (merr != MERR_NONE) {
        i->state->successfull_install = false;
    }

    return merr;
}

mender_err_t mender_installer_finish(struct mender_installer *i) {
    mender_err_t merr;

    LOGI("finish");

    if (!i->state) {
        LOGE("state is NULL, it looks like we never got started");
        return MERR_INVALID_STATE;
    }

    if (!i->state->successfull_install) {
        LOGE("Something went wrong while installing and installation is not finished yet.");
        merr = MERR_INSTALL_NOT_SUCCESSFULL;
        goto cleanup;
    }

    merr = MERR_NONE;

cleanup:
    if (i->state->device_end_needed) {
        LOGW("unexpected device state cleanup required. the update was probably aborted");
        merr = mender_device_install_update_end(i->device);
        if (merr) {
            LOGW("install_update_process_data failed");
        }
    }

    if (i->state->root_tar_ctx) {
        free_tar_ctx(i->stack, i->state->root_tar_ctx);
        i->state->root_tar_ctx = NULL;
    }

    mender_stack_give(i->stack, i->state, sizeof(*(i->state)));
    i->state = NULL;

    return merr;
}

#ifdef MENDER_ENABLE_TESTING
#include "../tests/installer.c"
#endif
