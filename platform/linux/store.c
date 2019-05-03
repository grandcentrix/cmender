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

#include <mender/platform/store.h>
#include <mender/platform/log.h>
#include <mender/internal/compiler.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>

static mender_err_t get_path(struct mender_store *store, const char *name, char *buf) {
    int rc = snprintf(buf, PATH_MAX, "%s/%s", store->path, name);
    if (rc < 0 || rc >= PATH_MAX)
        return MERR_OUT_OF_RESOURCES;

    return MERR_NONE;
}

int mender_store_has(struct mender_store *store, const char *key) {
    mender_err_t merr;
    int rc;
    struct stat sb;
    char path[PATH_MAX];

    merr = get_path(store, key, path);
    if (merr)
        return 0;

    rc = stat(path, &sb);
    if (rc)
        return 0;

    return 1;
}

mender_err_t mender_store_read_all(struct mender_store *store, const char *key, void *data,
        size_t maxlen, size_t *pactual)
{
    mender_err_t merr;
    int rc;
    int fd;
    ssize_t nbytes;
    struct stat sb;
    char path[PATH_MAX];

    merr = get_path(store, key, path);
    if (merr)
        return merr;

    rc = stat(path, &sb);
    if (rc)
        return MERR_NOT_FOUND;

    if (pactual)
        *pactual = sb.st_size;
    if ((size_t)sb.st_size > maxlen)
        return MERR_BUFFER_TOO_SMALL;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return MERR_UNKNOWN;

    nbytes = read(fd, data, sb.st_size);
    close(fd);
    if (nbytes < 0 || nbytes != (ssize_t)sb.st_size)
        return MERR_UNKNOWN;

    return MERR_NONE;
}

mender_err_t mender_store_write_all(struct mender_store *store, const char *key, const void *data, size_t len) {
    mender_err_t merr;
    int rc;
    int fd;
    ssize_t nbytes;
    char path[PATH_MAX];
    char tmppath[PATH_MAX];

    merr = get_path(store, key, path);
    if (merr)
        return merr;

    rc = snprintf(tmppath, sizeof(tmppath), "%s/tmpXXXXXX", store->path);
    if (rc < 0 || rc >= (int)sizeof(tmppath))
        return MERR_OUT_OF_RESOURCES;

    fd = mkstemp(tmppath);
    if (fd < 0) {
        LOGE("can't create tmp file at %s: %s", tmppath, strerror(errno));
        return MERR_UNKNOWN;
    }

    nbytes = write(fd, data, len);
    close(fd);
    if (nbytes < 0 || nbytes != (ssize_t)len)
        return MERR_UNKNOWN;

    rc = rename(tmppath, path);
    if (rc)
        return MERR_UNKNOWN;

    return MERR_NONE;
}

mender_err_t mender_store_remove(struct mender_store *store, const char *key) {
    mender_err_t merr;
    int rc;
    char path[PATH_MAX];

    merr = get_path(store, key, path);
    if (merr)
        return merr;

    rc = unlink(path);
    if (rc)
        return MERR_UNKNOWN;

    return MERR_NONE;
}

mender_err_t mender_platform_store_create(struct mender_store *store, const char *path) {
    memset(store, 0, sizeof(*store));

    store->path = path;

    return MERR_NONE;
}
