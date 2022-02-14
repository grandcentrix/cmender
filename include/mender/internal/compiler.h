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

#ifndef MENDER_INTERNAL_COMPILER_H
#define MENDER_INTERNAL_COMPILER_H

#ifndef containerof
#define containerof(ptr, type, member) \
    ((type *)((uintptr_t)(ptr) - offsetof(type, member)))
#endif

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef ROUNDUP
#define ROUNDUP(a, b) (((a) + ((b)-1)) & ~((b)-1))
#endif

#ifndef ROUNDDOWN
#define ROUNDDOWN(a, b) ((a) & ~((b)-1))
#endif

#ifndef SSIZE_MAX
#define SSIZE_MAX (SIZE_MAX / 2 - 1)
#endif

#endif /* MENDER_INTERNAL_COMPILER_H */
