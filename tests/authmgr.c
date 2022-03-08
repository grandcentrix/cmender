#include <mender/hexdump.h>

static struct mender_authmgr am;
static struct mender_store *store = (void*) 0xdeadbeef;
static struct mender_keystore *keystore = (void*) 0xd00df33d;
static struct mender_identity_data *id = (void*) 0xdeafd00d;

static void test_authmgr_all(void **state __unused) {
    mender_err_t merr;
    static char buf[1024];
    size_t actual = 0;
    const char *data = NULL;
    size_t datalen = 0;
    const char *sig = NULL;
    size_t siglen = 0;
    const char *token = NULL;
    size_t tokenlen = 0;

    static const char *TEST_IDENTITY_DATA = "test-identity-data";
    static const char *TEST_PEM = "test-pem";
    static const char *TEST_SIGNATURE = "signature";
    static const char expected[] = "dummy\0{\""
        "id_data\":\"test-identity-data\","
        "\"tenant_token\":\"dummy\","
        "\"pubkey\":\"test-pem\","
        "\"pubkeytype\":\"magic-keytype\"}\0signature";

    mender_keystore_load_expect(keystore, MERR_NONE);
    mender_authmgr_create(&am, store, keystore, id);

    mender_keystore_get_keytype_expect(keystore, "magic-keytype", MERR_NONE);
    mender_identity_data_write_expect(id, TEST_IDENTITY_DATA, strlen(TEST_IDENTITY_DATA), MERR_NONE);
    mender_keystore_get_public_pem_expect(keystore, TEST_PEM, strlen(TEST_PEM), MERR_NONE);
    mender_keystore_sign_expect(keystore, TEST_SIGNATURE, strlen(TEST_SIGNATURE), MERR_NONE);

    merr = mender_authmgr_generate_authdata(&am,
        buf, sizeof(buf), &actual,
        &data, &datalen,
        &sig, &siglen,
        &token, &tokenlen);
    assert_int_equal(merr, MERR_NONE);

    mender_hexdump(buf, actual);
    assert_int_equal(actual, sizeof(expected));
    assert_int_equal(memcmp(expected, buf, actual), 0);

    assert_ptr_equal(data, buf + 6);
    assert_int_equal(datalen, 104);

    assert_ptr_equal(sig, data + datalen + 1);
    assert_int_equal(siglen, strlen(TEST_SIGNATURE));

    assert_ptr_equal(token, buf);
    // "dummy"
    assert_int_equal(tokenlen, 5);
}

static const struct CMUnitTest tests_authmgr[] = {
    cmocka_unit_test(test_authmgr_all),
};

static int setup(void **state __unused) {
    mender_store_mocking_enabled = 1;
    mender_keystore_mocking_enabled = 1;
    mender_identity_data_mocking_enabled = 1;
    return 0;
}

static int teardown(void **state __unused) {
    mender_store_mocking_enabled = 0;
    mender_keystore_mocking_enabled = 0;
    mender_identity_data_mocking_enabled = 0;
    return 0;
}

int mender_test_run_authmgr(void) {
    return cmocka_run_group_tests(tests_authmgr, setup, teardown);
}
