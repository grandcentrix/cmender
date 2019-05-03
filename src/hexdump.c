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

#include <mender/hexdump.h>
#include <mender/platform/log.h>
#include <mender/internal/compiler.h>

static inline int mender_isprint(int c) {
    return ((c >= 0x20) && (c < 0x7f));
}

static ssize_t easy_snprintf(char *s, size_t n, const char *format, ...) {
    int rc;

    va_list args;
    va_start(args, format);
    rc = vsnprintf(s, n, format, args);
    va_end (args);

    if (rc < 0 || (size_t)rc >= n) {
        return -1;
    }

    return (ssize_t)rc;
}

#define BUF_SNPRINTF(buf, off, fmt, ...) easy_snprintf((buf) + (off), ARRAY_SIZE(buf) - (off), fmt, ##__VA_ARGS__)

#define _HEXDUMP_APPENDLINE(fmt, ...) do { \
    nbytes = BUF_SNPRINTF(line, linesz, fmt, ##__VA_ARGS__); \
    if (nbytes < 0) \
        goto err; \
    linesz += nbytes; \
} while(0)

void mender_hexdump(const void *_buf, size_t sz) {
    char line[79];
    size_t i;
    size_t j;
    const uint8_t *buf = _buf;
    ssize_t nbytes;

    (void)(buf);

    for (i = 0; i < sz; i += 16) {
        size_t linesz = 0;
        size_t toread = MIN(16, sz - i);

        // offset
        _HEXDUMP_APPENDLINE("%08zx ", i);

        // hexdump
        for (j = 0; j < 16; j++) {
            if (j < toread) {
                _HEXDUMP_APPENDLINE(" %s%02x", j==8?" ":"", buf[i + j]);
            }
            else {
                _HEXDUMP_APPENDLINE("%s   ", j==8?" ":"");
            }
        }

        _HEXDUMP_APPENDLINE("  |");

        // ascii
        for (j = 0; j < 16; j++) {
            if (j < toread) {
                _HEXDUMP_APPENDLINE("%c", mender_isprint(buf[i + j])?buf[i + j]:'.');
            }
            else {
                _HEXDUMP_APPENDLINE(" ");
            }
        }

        _HEXDUMP_APPENDLINE("|");

        LOGV("%s", line);
    }

    return;

err:
    LOGV("internal hexdump error");
}
#undef _HEXDUMP_APPENDLINE
