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

#include <mender/utils.h>
#include <mender/platform/log.h>

int mender_hex2int(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}

size_t mender_hex2bytes(const char *src, uint8_t *dst, size_t n) {
    size_t i;

    for (i = 0; i < n && mender_isxdigit(src[i*2]) && mender_isxdigit(src[i*2+1]); i++) {
        *dst = (uint8_t)((mender_hex2int(src[i*2])<<4) | mender_hex2int(src[i*2+1]));
        dst++;
    }

    return i*2;
}

mender_err_t mender_json_encode_str_inplace(char *buf, size_t maxsz, size_t *pactual) {
    size_t oldlen = 0;
    size_t newlen = 0;
    char *p;
    char unicodebuf[7];
    size_t srcpos;
    size_t dstpos;

    for (p=buf; *p; p++) {
        switch (*p) {
        case '\"':
        case '\\':
        case '\b':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
            newlen += 2;
            break;

        default:
            if (*p >= 32)
                newlen++;
            else
                newlen += 6;
            break;
        }

        oldlen++;
    }

    if (newlen + 1 > maxsz) {
        return MERR_BUFFER_TOO_SMALL;
    }

    srcpos = oldlen;
    dstpos = newlen;
    while(srcpos) {
        char c = buf[--srcpos];

        switch (c) {
        case '\"':
            if (dstpos < 2)
                return MERR_BUFFER_TOO_SMALL;
            buf[--dstpos] = '\"';
            buf[--dstpos] = '\\';
            break;
        case '\\':
            if (dstpos < 2)
                return MERR_BUFFER_TOO_SMALL;
            buf[--dstpos] = '\\';
            buf[--dstpos] = '\\';
            break;
        case '\b':
            if (dstpos < 2)
                return MERR_BUFFER_TOO_SMALL;
            buf[--dstpos] = 'b';
            buf[--dstpos] = '\\';
            break;
        case '\f':
            if (dstpos < 2)
                return MERR_BUFFER_TOO_SMALL;
            buf[--dstpos] = 'f';
            buf[--dstpos] = '\\';
            break;
        case '\n':
            if (dstpos < 2)
                return MERR_BUFFER_TOO_SMALL;
            buf[--dstpos] = 'n';
            buf[--dstpos] = '\\';
            break;
        case '\r':
            if (dstpos < 2)
                return MERR_BUFFER_TOO_SMALL;
            buf[--dstpos] = 'r';
            buf[--dstpos] = '\\';
            break;
        case '\t':
            if (dstpos < 2)
                return MERR_BUFFER_TOO_SMALL;
            buf[--dstpos] = 't';
            buf[--dstpos] = '\\';
            break;
        default:
            if (c >= 32) {
                if (dstpos < 1)
                    return MERR_BUFFER_TOO_SMALL;
                buf[--dstpos] = c;
            }
            else {
                if (dstpos < 6)
                    return MERR_BUFFER_TOO_SMALL;
                dstpos -= 6;
                sprintf(unicodebuf, "\\u%04x", c);
                memcpy(&buf[dstpos], unicodebuf, 6);
            }
        }
    }
    if (dstpos != 0) {
        return MERR_IMPLEMENTATION_BUG;
    }

    buf[newlen] = '\0';
    *pactual = newlen;
    return MERR_NONE;
}

mender_err_t mender_json_decode_str_inplace(char *buf, size_t sz, size_t *pnewsz) {
    size_t srcpos = 0;
    size_t dstpos = 0;

    while (srcpos < sz) {
        char c = buf[srcpos++];

        if (c == '\\') {
            size_t nleft;
            char e1;

            nleft = sz - srcpos;
            if (nleft < 1) {
                LOGE("'\\' at the end of the string");
                return MERR_INVALID_ARGUMENTS;
            }

            e1 = buf[srcpos++];
            switch (e1) {
                case '\"':
                    buf[dstpos++] = '\"';
                    break;

                case '\\':
                    buf[dstpos++] = '\\';
                    break;

                case 'b':
                    buf[dstpos++] = '\b';
                    break;

                case 'f':
                    buf[dstpos++] = '\f';
                    break;

                case 'n':
                    buf[dstpos++] = '\n';
                    break;

                case 'r':
                    buf[dstpos++] = '\r';
                    break;

                case 't':
                    buf[dstpos++] = '\t';
                    break;

                case 'u': {
                    int u0;
                    int u1;
                    int u2;
                    int u3;
                    uint8_t d0;
                    uint8_t d1;

                    if (nleft < 4) {
                        LOGE("unicode escape sequence is too short");
                        return MERR_INVALID_ARGUMENTS;
                    }

                    u0 = mender_hex2int(buf[srcpos++]);
                    if (u0 < 0) return MERR_INVALID_ARGUMENTS;

                    u1 = mender_hex2int(buf[srcpos++]);
                    if (u1 < 0) return MERR_INVALID_ARGUMENTS;

                    u2 = mender_hex2int(buf[srcpos++]);
                    if (u2 < 0) return MERR_INVALID_ARGUMENTS;

                    u3 = mender_hex2int(buf[srcpos++]);
                    if (u3 < 0) return MERR_INVALID_ARGUMENTS;

                    d0 = (u0 << 4 | u1);
                    d1 = (u2 << 4 | u3);

                    if (d0) {
                        LOGE("can't represent unicode character: %02x%02x", d0, d1);
                        return MERR_INVALID_ARGUMENTS;
                    }
                    buf[dstpos++] = d1;

                    break;
                }

                default:
                    LOGE("unsupported escape character: %c", e1);
                    return MERR_INVALID_ARGUMENTS;
            }
        }
        else if(srcpos != dstpos) {
            buf[dstpos++] = c;
        }
    }

    buf[dstpos++] = '\0';

    if (pnewsz)
        *pnewsz = dstpos;

    return MERR_NONE;
}

#ifdef MENDER_ENABLE_TESTING
#include "../tests/utils.c"
#endif
