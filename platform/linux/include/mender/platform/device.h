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

#ifndef MENDER_PLATFORM_DEVICE_H
#define MENDER_PLATFORM_DEVICE_H

#include <mender/device.h>
#include <mender/store.h>

struct mender_device {
    struct mender_store *store;

    int fd;
};

void mender_platform_device_create(struct mender_device *dev, struct mender_store *store);


#endif /* MENDER_PLATFORM_DEVICE_H */
