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

#ifndef MENDER_PLATFORM_LOG_H
#define MENDER_PLATFORM_LOG_H

#include <stdio.h>

#define LOG_COLOR_RESET   "\x1B[0m"
#define LOG_COLOR_BLUE     75
#define LOG_COLOR_DEFAULT 231
#define LOG_COLOR_GREEN    40
#define LOG_COLOR_ORANGE  166
#define LOG_COLOR_RED     196
#define LOG_COLOR_YELLOW  226

#define LOG_INT_TO_STR(n) #n
#define RELATIVE_FILEPATH (strrchr(__FILE__, '/')?strrchr(__FILE__, '/')+1:__FILE__)

#define LOG_INTERNAL(c, fmt, ...) fprintf(stderr, "\x1B[38;5;" LOG_INT_TO_STR(c) "m" "[%s: %5u] " fmt LOG_COLOR_RESET "\n", RELATIVE_FILEPATH, __LINE__, ##__VA_ARGS__)
#define LOGD(fmt, ...) LOG_INTERNAL(LOG_COLOR_BLUE, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) LOG_INTERNAL(LOG_COLOR_RED, fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) LOG_INTERNAL(LOG_COLOR_GREEN, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) LOG_INTERNAL(LOG_COLOR_ORANGE, fmt, ##__VA_ARGS__)
#define LOGV(fmt, ...) LOG_INTERNAL(LOG_COLOR_DEFAULT, fmt, ##__VA_ARGS__)

#endif /* MENDER_PLATFORM_LOG_H */
