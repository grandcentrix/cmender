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

#ifndef MENDER_ERROR_H
#define MENDER_ERROR_H

#include <mender/platform/types.h>

#define MENDER_ERR_FATAL(e) (MENDER_ERR_VAL((e)) | 0x80000000)
#define MENDER_ERR_VAL(e) ((e) & 0x7fffffff)
#define MENDER_ERR_ISFATAL(e) (((e) & 0x80000000) == 0x80000000)
typedef uint32_t mender_err_t;

/* generic errors */
#define MERR_NONE 0
#define MERR_NOT_FOUND 1
#define MERR_EXISTS 2
#define MERR_BUSY 3
#define MERR_INVALID_ARGUMENTS 4
#define MERR_OUT_OF_RESOURCES 5
#define MERR_IMPLEMENTATION_BUG 6
#define MERR_UNSUPPORTED 7
#define MERR_INVALID_STATE 8
#define MERR_TRY_AGAIN 9
#define MERR_UNKNOWN 10
#define MERR_BUFFER_TOO_SMALL 11
#define MERR_TIMEOUT 12
#define MERR_VERSION_INVALID 13
#define MERR_VERSION_OLD 14

/* state */
#define MERR_UNSUPPORTED_STATE_DATA 20
#define MERR_FAILED_TO_RESTORE_STATE_DATA 21
#define MERR_REBOOT_FAILED 22
#define MERR_INVALID_STATE_STORED 23
#define MERR_FAILED_TO_PERFORM_UPGRADE_CHECK 24
#define MERR_UPDATE_FAILED 25
#define MERR_STATEMACHINE_STOPPED 26

/* client */
#define MERR_CLIENT_UNAUTHORIZED 40
#define MERR_DEPLOYMENT_ABORTED 41
#define MERR_NO_ARTIFACT_NAME 42
#define MERR_INVALID_HTTP_STATUS 43
#define MERR_INVALID_DATA 44
#define MERR_UPDATE_INCOMPATIBLE 45

/* http */
#define MERR_NO_HTTP_TRANSPORT 50
#define MERR_SSL_HANDSHAKE_ERROR 51
#define MERR_SSL_CERTIFICATE_ERROR 52

/* keystore */
#define MERR_KEYSTORE_NOKEYS 60

/* json */
#define MERR_JSON_TYPE_ERROR 70
#define MERR_JSON_KEY_MISSING 71
#define MERR_JSON_UNEXPECTED_KEY 72
#define MERR_JSON_INVALID 73
#define MERR_JSON_PARTIAL 74

/* installer */
#define MERR_INSTALL_NOT_SUCCESSFULL 80
#define MERR_INVALID_MANIFEST 81
#define MERR_CHECKSUM_WRONG 82
#define MERR_MISSING_FILE 82
#define MERR_WRONG_ARTIFACT 83

#endif /* MENDER_ERROR_H */
