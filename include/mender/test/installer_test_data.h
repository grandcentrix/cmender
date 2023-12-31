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

#ifndef MENDER_INSTALLER_TEST_DATA_H
#define MENDER_INSTALLER_TEST_DATA_H

#include <mender/platform/types.h>

/*
 * Known good artifact generated by mender-artifact
 *
 * Test artifact:
 * Artifact name: upgrade
 * Device: testdevice
 * Filename: rootfs.sdimage(2 kiB of random)
 * no compression
 */
extern const uint8_t mender_installer_test_artifact[];
extern const size_t mender_installer_test_artifact_len;

/*
 * Parameters to tweak a generated mender artifact for testing purposes
 */
struct mender_installer_test_artifact_configuration {
    // Change one entry to a special value
    const char *device_type, *artifact_name, *file_name, *version, *mender_format, *type_info;

    // Generate a faulty sha256 sum for a file
    bool fake_data_sum, fake_header_sum, fake_version_sum;

    // Add a file twice to artifact
    bool double_version, double_files, double_type_info;

    // Omit a whole file file from the artifact
    bool omit_version, omit_header_info, omit_files, omit_type_info, omit_manifest, omit_header_tar, omit_data;

    // Append an empty file instead of the correct version
    bool empty_manifest, empty_version;

    // Mess with version
    bool version_omit_closing_brace;

    // Mess with the manifest
    bool manifest_too_short_sum, manifest_omit_filenames;

    // Mess with headers/0000/files
    bool files_add_fake_file;

    // Omit a key from json files
    bool json_omit_format, json_omit_version, json_omit_device_types, json_omit_artifact_name, json_omit_files, json_omit_type_info;

    // Append a not expected fake key
    bool json_add_to_version, json_add_to_type_info, json_add_to_header_info, json_add_to_files;

    // Append an unexpected file a the end of the artifact
    bool append_file_at_end;

    // Mess withe the size header field of the version file
    bool version_fake_size, version_test_size;
    size_t version_size;

    // ------------------------------------------------------------------------------------------------------------------
    // Position of files inside the generated artifact(written by mender_installer_test_make_artifact())
    size_t version_start, manifest_start, header_tar_start, header_info_start, headers_files_start, headers_type_info_start, data_tar_start, data_start;
};

size_t mender_installer_test_make_artifact(struct mender_installer_test_artifact_configuration *c, uint8_t **artifact);

#endif /* MENDER_INSTALLER_TEST_DATA_H */
