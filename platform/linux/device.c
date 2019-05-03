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

#include <mender/platform/device.h>
#include <mender/platform/log.h>
#include <mender/internal/compiler.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

mender_err_t mender_device_reboot(struct mender_device *dev __unused) {
    exit(0);
    return MERR_UNKNOWN;
}

mender_err_t mender_device_swap_partitions(struct mender_device *dev __unused) {
    return MERR_NONE;
}

mender_err_t mender_device_install_update_start(struct mender_device *dev, uint64_t size __unused) {
    dev->fd = open("/tmp/mender-root.bin", O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (dev->fd < 0)
        return MERR_UNKNOWN;

    return MERR_NONE;
}

mender_err_t mender_device_install_update_process_data(struct mender_device *dev, const void *data, size_t len) {
    ssize_t nbytes = write(dev->fd, data, len);
    if (nbytes != (ssize_t) len)
        return MERR_UNKNOWN;

    return MERR_NONE;
}

mender_err_t mender_device_install_update_end(struct mender_device *dev) {
    close(dev->fd);

    return MERR_NONE;
}

mender_err_t mender_device_enable_updated_partition(struct mender_device *dev) {
    struct mender_store *store = dev->store;
    bool has = true;
    return mender_store_write_all(store, "upgrade_available", &has, sizeof(has));
}

mender_err_t mender_device_commit_update(struct mender_device *dev) {
    struct mender_store *store = dev->store;
    bool has;
    mender_err_t err;

    err = mender_device_has_update(dev, &has);
    if (err)
        return err;

    if (has) {
        LOGI("Commiting update");
        has = false;
        return mender_store_write_all(store, "upgrade_available", &has, sizeof(has));
    }

    return MERR_NONE;
}

mender_err_t mender_device_has_update(struct mender_device *dev, bool *phasupdate) {
    struct mender_store *store = dev->store;
    mender_err_t err;
    size_t nbytes;

    err = mender_store_read_all(store, "upgrade_available", phasupdate, sizeof(*phasupdate), &nbytes);
    if (err || nbytes != sizeof(*phasupdate)) {
        if (err != MERR_NOT_FOUND)
            return err;

        *phasupdate = false;
    }

    return MERR_NONE;
}

void mender_platform_device_create(struct mender_device *dev, struct mender_store *store) {
    memset(dev, 0, sizeof(*dev));
    dev->store = store;
}
