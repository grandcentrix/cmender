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

#ifdef CONFIG_MENDER_SEMVER
mender_err_t check_semver(const char *current_version, const char *new_version) {
    bool version_same = true;
    bool version_higher = false;

    bool local_version_higher;
    bool local_version_same;
    int state = 0;

    size_t i = 0;
    size_t j = 0;

    ssize_t n;
    ssize_t m;

    while (new_version[j] && state < 3) {
        /* major, minor and patch */

        for (; current_version[i] && current_version[i] != '.'; i++) {
            if (!mender_isdigit(current_version[i])) {
                if (state == 2 && (current_version[i] == '-' || current_version[i] == '+')) {
                    /* pre-release and build will follow */
                    break;
                }
                /* Current version is not in semver format. Default to new version is newer */
                goto end;
            }
        }
        for (; new_version[j] && new_version[j] != '.'; j++) {
            if (!mender_isdigit(new_version[j])) {
                if (state == 2 && (new_version[j] == '-' || new_version[j] == '+')) {
                    /* pre-release and build will follow */
                    break;
                }
                /* New version is not in semver format, decline the update */
                goto invalid;
            }
        }

        local_version_higher = true;
        local_version_same = true;
        /* Compare version number from the back.
         * Next higher position digit overwrites result from lower position, exept it
         * matches between old and new version.
         */
        for (n = i - 1, m = j - 1; n >= 0 && m >= 0 && current_version[n] != '.'
                                   && new_version[m] != '.'; n--, m--) {
            if (new_version[m] > current_version[n]) {
                local_version_higher = true;
                local_version_same = false;
            } else if (new_version[m] < current_version[n]) {
                local_version_higher = false;
                local_version_same = false;
            }
        }

        /* If the current version is longer and the prefix does not consist from zeros,
         * the current version is newer
         */
        for (; n >= 0 && current_version[n] != '.'; n--) {
            if (current_version[n] != '0') {
                local_version_higher = false;
                local_version_same = false;
            }
        }
        /* If the new version is longer and the prefix does not consist from zeros,
         * the new version is newer
         */
        for (; m >= 0 && new_version[m] != '.'; m--) {
            if (new_version[m] != '0') {
                local_version_higher = true;
                local_version_same = false;
            }
        }

        /* If the current version number part is higher and all until now were the same,
         * the overall version number is higher
         */
        if (local_version_higher && !local_version_same && version_same) {
            version_higher = true;
        }
        if (!local_version_same) {
            version_same = false;
        }

        if (state < 2) {
            if (!current_version[i]) {
                /* Current version is not in semver format. Default to new version is newer */
                goto end;
            }
            if (!new_version[j]) {
                /* New version is not in semver format, decline the update */
                goto invalid;
            }
            i++;
            j++;
        }
        state++;
    }

    /* We must got major, minor and patch version */
    if (state != 3) {
        goto invalid;
    }

    /* pre-release and build */
    for (; new_version[j]; j++) {
        if (!mender_isdigit(new_version[j]) && !mender_isletter(new_version[j]) &&
            new_version[j] != '-' && new_version[j] != '+' && new_version[j] != '.') {
            goto invalid;
        }
    }

    if (!version_higher && !version_same) {
        return MERR_VERSION_OLD;
    }
    if (version_same) {
        return MERR_EXISTS;
    }

end:
    return MERR_NONE;
invalid:
    return MERR_VERSION_INVALID;
}
#endif /* CONFIG_MENDER_SEMVER */

#ifdef MENDER_ENABLE_TESTING
#include "../tests/utils.c"
#endif
