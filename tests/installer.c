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

#include <mender/test/common.h>
#include <mender/test/installer_test_data.h>

static struct mender_installer installer;
static struct mender_stack stack;

#ifndef MENDER_INSTALLER_TEST_CHUNK_SIZE
#define MENDER_INSTALLER_TEST_CHUNK_SIZE 16
#endif

#ifndef MENDER_INSTALLER_TEST_STACK_SIZE
#define MENDER_INSTALLER_TEST_STACK_SIZE 4096
#endif

static char buf[MENDER_INSTALLER_TEST_CHUNK_SIZE];
static char stack_buf[MENDER_INSTALLER_TEST_STACK_SIZE];
static struct mender_device *device = (void*)0xdeadbeef;

static void setup_installer(void) {
    memset(&installer, 0, sizeof(struct mender_installer));
    memset(&stack, 0, sizeof(struct mender_stack));
    memset(buf, 0, MENDER_INSTALLER_TEST_CHUNK_SIZE);

    mender_stack_create(&stack, stack_buf, sizeof(stack_buf));
    mender_installer_create(&installer, device, &stack, "testdevice");
}

static void expect_mender_device_install_update_start(struct mender_device *the_device, size_t the_size) {
    expect_function_call(mender_device_install_update_start_test);
    expect_value(mender_device_install_update_start_test, dev, cast_ptr_to_largest_integral_type(the_device));
    expect_value(mender_device_install_update_start_test, size, the_size);
    will_return_always(mender_device_install_update_start_test, MERR_NONE);
}

static void expect_calls_mender_device_install_update_process_data(struct mender_device *the_device, void *the_buf, size_t buflen, size_t cnt) {
    expect_function_calls(mender_device_install_update_process_data_test, cnt);
    expect_value_count(mender_device_install_update_process_data_test, dev, cast_ptr_to_largest_integral_type(the_device), cnt);
    // As the installer should stream the data without copying and everything is alinged, we can just check the pointer value here
    expect_value_count(mender_device_install_update_process_data_test, data, cast_ptr_to_largest_integral_type(the_buf), cnt);
    expect_value_count(mender_device_install_update_process_data_test, len, buflen, cnt);
    will_return_always(mender_device_install_update_process_data_test, MERR_NONE);
}

static void expect_mender_device_install_update_end(struct mender_device *the_device) {
    expect_function_call(mender_device_install_update_end_test);
    expect_value(mender_device_install_update_end_test, dev, cast_ptr_to_largest_integral_type(the_device));
    will_return_always(mender_device_install_update_end_test, MERR_NONE);
}

static void test_installer_install(void **state __unused) {
    setup_installer();

    expect_mender_device_install_update_start(device, 2048);
    expect_calls_mender_device_install_update_process_data(device, buf, MENDER_INSTALLER_TEST_CHUNK_SIZE, 2048/MENDER_INSTALLER_TEST_CHUNK_SIZE);
    expect_mender_device_install_update_end(device);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    // Simulating a chunk-wise read here
    for (size_t pos = 0; pos < mender_installer_test_artifact_len; pos += MENDER_INSTALLER_TEST_CHUNK_SIZE) {
        memcpy(buf, mender_installer_test_artifact+pos, MENDER_INSTALLER_TEST_CHUNK_SIZE);
        assert_int_equal(mender_installer_process_data(&installer, buf, MENDER_INSTALLER_TEST_CHUNK_SIZE), MERR_NONE);
    }
    assert_int_equal(mender_installer_finish(&installer), MERR_NONE);
}

static void test_installer_install_generated(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    struct mender_installer_test_artifact_configuration conf = {
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    expect_mender_device_install_update_start(device, 2048);
    expect_calls_mender_device_install_update_process_data(device, buf, MENDER_INSTALLER_TEST_CHUNK_SIZE, 2048/MENDER_INSTALLER_TEST_CHUNK_SIZE);
    expect_mender_device_install_update_end(device);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    for (size_t pos = 0; pos < generated_artifact_len; pos += MENDER_INSTALLER_TEST_CHUNK_SIZE) {
        memcpy(buf, generated_artifact+pos, MENDER_INSTALLER_TEST_CHUNK_SIZE);
        assert_int_equal(mender_installer_process_data(&installer, buf, MENDER_INSTALLER_TEST_CHUNK_SIZE), MERR_NONE);
    }
    assert_int_equal(mender_installer_finish(&installer), MERR_NONE);

    free(generated_artifact);
}

static void test_installer_wrong_artifact(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    struct mender_installer_test_artifact_configuration conf = {
        .artifact_name = "fake-artifact"
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_WRONG_ARTIFACT);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_unsupported_artifact_run(struct mender_installer_test_artifact_configuration *conf) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_UNSUPPORTED);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_unsupported_artifact(void **state __unused) {
    test_installer_unsupported_artifact_run(&(struct mender_installer_test_artifact_configuration){.version="3"});
    test_installer_unsupported_artifact_run(&(struct mender_installer_test_artifact_configuration){.mender_format="fake"});
    test_installer_unsupported_artifact_run(&(struct mender_installer_test_artifact_configuration){.device_type = "fake-device"});
    test_installer_unsupported_artifact_run(&(struct mender_installer_test_artifact_configuration){.type_info="fake-image"});
    test_installer_unsupported_artifact_run(&(struct mender_installer_test_artifact_configuration){.files_add_fake_file=true});
}
static void test_installer_version_partial(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    struct mender_installer_test_artifact_configuration conf = {
        .version_omit_closing_brace=true
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_JSON_PARTIAL);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_invalid_manifest(struct mender_installer_test_artifact_configuration *conf) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_INVALID_MANIFEST);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_manifest_invalid(void **state __unused) {
    test_installer_invalid_manifest(&(struct mender_installer_test_artifact_configuration){.manifest_too_short_sum=true});
    test_installer_invalid_manifest(&(struct mender_installer_test_artifact_configuration){.manifest_omit_filenames=true});
}

static void test_installer_data_sha_wrong(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    struct mender_installer_test_artifact_configuration conf = {
        .fake_data_sum=true
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    expect_mender_device_install_update_start(device, 2048);
    expect_calls_mender_device_install_update_process_data(device, generated_artifact+conf.data_start, 2048, 1);
    expect_mender_device_install_update_end(device);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_CHECKSUM_WRONG);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_version_sha_wrong(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    struct mender_installer_test_artifact_configuration conf = {
        .fake_version_sum=true
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_CHECKSUM_WRONG);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_header_sha_wrong(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    struct mender_installer_test_artifact_configuration conf = {
        .fake_header_sum=true
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_CHECKSUM_WRONG);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_json_missing(struct mender_installer_test_artifact_configuration *conf) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_JSON_KEY_MISSING);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_json_omit(void **state __unused) {
    test_installer_json_missing(&(struct mender_installer_test_artifact_configuration){.json_omit_version=true});
    test_installer_json_missing(&(struct mender_installer_test_artifact_configuration){.json_omit_format=true});
    test_installer_json_missing(&(struct mender_installer_test_artifact_configuration){.json_omit_device_types=true});
    test_installer_json_missing(&(struct mender_installer_test_artifact_configuration){.json_omit_artifact_name=true});
    test_installer_json_missing(&(struct mender_installer_test_artifact_configuration){.json_omit_files=true});
    test_installer_json_missing(&(struct mender_installer_test_artifact_configuration){.json_omit_type_info=true});
}

static void test_installer_json_too_much(struct mender_installer_test_artifact_configuration *conf) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_JSON_UNEXPECTED_KEY);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_json_add_key(void **state __unused) {
    test_installer_json_too_much(&(struct mender_installer_test_artifact_configuration){.json_add_to_version=true});
    test_installer_json_too_much(&(struct mender_installer_test_artifact_configuration){.json_add_to_header_info=true});
    test_installer_json_too_much(&(struct mender_installer_test_artifact_configuration){.json_add_to_files=true});
    test_installer_json_too_much(&(struct mender_installer_test_artifact_configuration){.json_add_to_type_info=true});
}

static const char *_installer_expected_file(void) {
    if (installer.state->root_tar_ctx->state == MENDER_TAR_STATE_RECV_HDR) {
        return installer.state->root_tar_ctx->cfg->files[installer.state->root_tar_ctx->table_pos].name;
    }
    else if (installer.state->root_tar_ctx->cfg->files[installer.state->root_tar_ctx->table_pos].type == MENDER_INSTALLER_FILE_TYPE_TAR) {
        return installer.state->root_tar_ctx->u.tar.subtar->cfg->files[installer.state->root_tar_ctx->u.tar.subtar->table_pos].name;
    }

    return NULL;
}

static void test_installer_missing_file(struct mender_installer_test_artifact_configuration *conf, const char *expected_file, mender_err_t expected_merr) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), expected_merr);
    if (expected_file != NULL)
        assert_string_equal(_installer_expected_file(), expected_file);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_missing_data_file(struct mender_installer_test_artifact_configuration *conf) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    // In this case, the process_data function should return with no error, as it just expect more data. In the end, the update was not successfull
    // so the installer_finish function should cause an error
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_NONE);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_missing_files(void **state __unused) {
    test_installer_missing_file(&(struct mender_installer_test_artifact_configuration){.omit_version=true}, "version", MERR_INVALID_STATE);
    test_installer_missing_file(&(struct mender_installer_test_artifact_configuration){.omit_manifest=true}, "manifest", MERR_INVALID_STATE);
    test_installer_missing_file(&(struct mender_installer_test_artifact_configuration){.omit_header_info=true}, "header-info", MERR_INVALID_STATE);
    test_installer_missing_file(&(struct mender_installer_test_artifact_configuration){.omit_files=true}, NULL, MERR_MISSING_FILE);
    test_installer_missing_file(&(struct mender_installer_test_artifact_configuration){.omit_type_info=true}, NULL, MERR_MISSING_FILE);
    test_installer_missing_file(&(struct mender_installer_test_artifact_configuration){.omit_header_tar=true}, "header.tar", MERR_INVALID_STATE);
    test_installer_missing_data_file(&(struct mender_installer_test_artifact_configuration){.omit_data=true});
}

static void test_installer_double_file(struct mender_installer_test_artifact_configuration *conf, mender_err_t expected_merr) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), expected_merr);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_double_files(void **state __unused) {
    test_installer_double_file(&(struct mender_installer_test_artifact_configuration){.double_version=true}, MERR_INVALID_STATE);
    test_installer_double_file(&(struct mender_installer_test_artifact_configuration){.double_files=true}, MERR_UNSUPPORTED);
    test_installer_double_file(&(struct mender_installer_test_artifact_configuration){.double_type_info=true}, MERR_UNSUPPORTED);
}

static void test_installer_version_zero_length(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;
    struct mender_installer_test_artifact_configuration conf = {
        .version_test_size=true,
        .version_size=0,
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    // The installer should try to parse a zero length version file, but expect an object here. This should result in an MERR_JSON_TYPE_ERROR
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_JSON_TYPE_ERROR);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_version_wrong_size_field(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;
    struct mender_installer_test_artifact_configuration conf = {
        .version_fake_size=true,
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    // The tar headers size field just contains "random" text, which should be parsed as zero and therefore the json parser should fail as above
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_JSON_TYPE_ERROR);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_version_too_big(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;
    struct mender_installer_test_artifact_configuration conf = {
        .version_test_size=true,
        .version_size=666,
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    // A too big size in the versions header should make the parser not to find the manifest file
    assert_int_not_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_NONE);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static void test_installer_file_after_data(void **state __unused) {
    size_t generated_artifact_len;
    uint8_t *generated_artifact;

    struct mender_installer_test_artifact_configuration conf = {
        .append_file_at_end=true,
    };

    setup_installer();

    generated_artifact_len = mender_installer_test_make_artifact(&conf, &generated_artifact);

    expect_mender_device_install_update_start(device, 2048);
    expect_calls_mender_device_install_update_process_data(device, generated_artifact+conf.data_start, 2048, 1);
    expect_mender_device_install_update_end(device);

    assert_int_equal(mender_installer_begin(&installer, "upgrade"), MERR_NONE);
    assert_int_equal(mender_installer_process_data(&installer, generated_artifact, generated_artifact_len), MERR_INVALID_STATE);
    assert_int_equal(mender_installer_finish(&installer), MERR_INSTALL_NOT_SUCCESSFULL);

    free(generated_artifact);
}

static const struct CMUnitTest tests_installer[] = {
    cmocka_unit_test(test_installer_install),
    cmocka_unit_test(test_installer_install_generated),
    cmocka_unit_test(test_installer_wrong_artifact),
    cmocka_unit_test(test_installer_unsupported_artifact),
    cmocka_unit_test(test_installer_version_partial),
    cmocka_unit_test(test_installer_manifest_invalid),
    cmocka_unit_test(test_installer_data_sha_wrong),
    cmocka_unit_test(test_installer_version_sha_wrong),
    cmocka_unit_test(test_installer_header_sha_wrong),
    cmocka_unit_test(test_installer_json_omit),
    cmocka_unit_test(test_installer_json_add_key),
    cmocka_unit_test(test_installer_missing_files),
    cmocka_unit_test(test_installer_double_files),
    cmocka_unit_test(test_installer_version_zero_length),
    cmocka_unit_test(test_installer_version_wrong_size_field),
    cmocka_unit_test(test_installer_version_too_big),
    cmocka_unit_test(test_installer_file_after_data),
};

static int setup(void **state __unused) {
    mender_device_mocking_enabled = 1;
    return 0;
}

static int teardown(void **state __unused) {
    mender_device_mocking_enabled = 0;
    return 0;
}

int mender_test_run_installer(void) {
    return cmocka_run_group_tests(tests_installer, setup, teardown);
}
