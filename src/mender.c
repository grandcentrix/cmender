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

#include <mender/mender.h>
#include <mender/internal/compiler.h>
#include <mender/platform/log.h>

#define MENDER_VERSION_STR "1.5.0"

static mender_err_t bootstrap(struct mender *mender) {
    struct mender_authmgr *authmgr = mender->authmgr;
    mender_err_t merr;

    if (!mender_authmgr_has_key(authmgr) || mender->force_bootstrap) {
        LOGI("device keys not present or bootstrap forced, generating");

        merr = mender_authmgr_generate_key(authmgr);
        if (merr) {
            return MENDER_ERR_FATAL(merr);
        }

    }

    mender->force_bootstrap = false;
    return MERR_NONE;
}

/* Controller */
bool mender_is_authorized(struct mender *mender) {
    struct mender_authmgr *authmgr = mender->authmgr;

    if (mender_authmgr_is_authorized(authmgr)) {
        LOGI("authorization data present and valid");
        return true;
    }

    return false;
}

static void client_auth_cb(void *ctx, mender_err_t auth_err, void *buf, size_t len) {
    struct mender *mender = ctx;
    struct mender_authmgr *authmgr = mender->authmgr;
    mender_err_t merr;

    if (auth_err) {
        if (auth_err == MERR_CLIENT_UNAUTHORIZED) {
            /* make sure to remove auth token once device is rejected */
            if (mender_authmgr_remove_auth_token(authmgr)) {
                LOGW("can not remove rejected authentication token");
            }
        }

        LOGE("authorization request failed: %08x", auth_err);
        merr = auth_err;
    }
    else {
        merr = mender_authmgr_set_token(authmgr, buf, len);
        if (merr) {
            LOGE("failed to parse authorization response: %08x", merr);
        }
        else {
            LOGI("successfuly received new authorization data");
        }
    }

    mender_client_auth_finish_request(&mender->client_auth);

    if (mender->auth_cb) {
        mender_on_result_t cb = mender->auth_cb;
        void *cbctx = mender->auth_cbctx;

        mender->auth_cb = NULL;
        mender->auth_cbctx = NULL;

        cb(cbctx, merr);
    }
}

void mender_authorize(struct mender *mender, mender_on_result_t cb, void *cbctx) {
    struct mender_authmgr *authmgr = mender->authmgr;
    mender_err_t merr;

    if (mender->auth_cb) {
        LOGE("another auth request is already running");
        cb(cbctx, MERR_BUSY);
        return;
    }

    if (mender_authmgr_is_authorized(authmgr)) {
        LOGI("authorization data present and valid, skipping authorization attempt");
        cb(cbctx, MERR_NONE);
        return;
    }

    merr = bootstrap(mender);
    if (merr) {
        LOGE("bootstrap failed: %08x", merr);
        cb(cbctx, merr);
        return;
    }

    mender->auth_cb = cb;
    mender->auth_cbctx = cbctx;

    merr = mender_client_auth_request(&mender->client_auth,
        mender->server_url, client_auth_cb, mender);
    if (merr) {
        LOGE("authorization request failed: %08x", merr);
        mender->auth_cb = NULL;
        mender->auth_cbctx = NULL;
        cb(cbctx, merr);
        return;
    }
}

mender_err_t mender_get_current_artifact_name(struct mender *mender, const char **pname) {
    *pname = mender->current_artifact_name;
    return MERR_NONE;
}

mender_duration_t mender_get_update_poll_interval(struct mender *mender) {
    return mender->update_poll_interval;
}

mender_time_t mender_get_scheduled_update_time(struct mender *mender) {
    if (mender->get_update_check_time != NULL)
        return mender->get_update_check_time();

    return 0;
}

mender_duration_t mender_get_inventory_poll_interval(struct mender *mender) {
    return mender->inventory_poll_interval;
}

mender_duration_t mender_get_retry_poll_interval(struct mender *mender) {
    return mender->retry_poll_interval;
}

mender_err_t mender_has_upgrade(struct mender *mender, bool *phasupgrade) {
    struct mender_device *device = mender->device;
    bool has;
    mender_err_t err;

    err = mender_device_has_update(device, &has);
    if (err) {
        *phasupgrade = false;
        return MENDER_ERR_FATAL(err);
    }

    *phasupgrade = has;
    return MERR_NONE;
}

static void check_update_cb(void *ctx, mender_err_t err);

static void check_update_reauth_cb(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;
    mender_err_t merr;

    if (err) {
        LOGW("Reauthorization failed with error: %08x", err);
        check_update_cb(mender, MERR_CLIENT_UNAUTHORIZED);
    }
    else {
        merr = mender_client_update_get(&mender->client_update,
            mender->server_url, mender->current_artifact_name,
            mender->device_type, mender->check_ur, check_update_cb, mender);
        if (merr) {
            check_update_cb(mender, merr);
            return;
        }
    }
}

static void check_update_cb(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;
    mender_err_t cbret;

    if (err) {
        /* remove authentication token if device is not authorized */
        if (MENDER_ERR_VAL(err) == MERR_CLIENT_UNAUTHORIZED) {
            if (mender_authmgr_remove_auth_token(mender->authmgr)) {
                LOGW("can not remove rejected authentication token");
            }

            if (mender->nattempts == 0) {
                LOGI("Device unauthorized; attempting reauthorization");

                mender->nattempts++;
                mender_authorize(mender, check_update_reauth_cb, mender);
                return;
            }
        }

        if (MENDER_ERR_VAL(err) == MERR_NOT_FOUND) {
            LOGD("no updates available");
            cbret = err;
            goto do_callback;
        }

        LOGE("Error receiving scheduled update data: %x", err);
        cbret = MENDER_ERR_VAL(err);
        goto do_callback;
    }

    LOGD("received update response: %s", mender->check_ur->id);

    if (!strcmp(mender->check_ur->artifact_name, mender->current_artifact_name)) {
        LOGI("Attempting to upgrade to currently installed artifact name, not performing upgrade.");
        cbret = MERR_EXISTS;
        goto do_callback;
    }

    cbret = MERR_NONE;

do_callback:
    if (mender->cb) {
        mender_on_result_t cb = mender->cb;
        void *cbctx = mender->cbctx;

        mender->cb = NULL;
        mender->cbctx = NULL;
        mender->check_ur = NULL;
        mender->nattempts = 0;

        cb(cbctx, cbret);
    }
    else {
        LOGW("no callback set");
    }
}

void mender_check_update(struct mender *mender, struct mender_update_response *ur, mender_on_result_t cb, void *cbctx) {
    mender_err_t merr;
    const char *artifact_name;
    const char *device_type;

    if (mender->cb) {
        LOGE("another request is already running");
        cb(cbctx, MERR_BUSY);
        return;
    }

    merr = mender_get_current_artifact_name(mender, &artifact_name);
    if (merr || !artifact_name || !artifact_name[0]) {
        LOGE("could not get the current artifact name");

        if (!artifact_name) {
            LOGE("artifact name is NULL");
        }
        else if (!artifact_name[0]) {
            LOGE("artifact name is empty");
        }

        LOGE(
            "could not read the artifact name. "
            "This is a necessary condition in order for a mender update to finish safely. "
            "Please give the current artifact a name. err: %x",
            merr
        );
        cb(cbctx, MERR_NO_ARTIFACT_NAME);
        return;
    }

    device_type = mender->device_type;
    if (!device_type) {
        LOGE("Unable to verify the existing hardware. Update will continue anyways");
    }

    mender->nattempts = 0;
    mender->cb = cb;
    mender->cbctx = cbctx;
    mender->check_ur = ur;

    merr = mender_client_update_get(&mender->client_update,
        mender->server_url, artifact_name, device_type, ur, check_update_cb, mender);
    if (merr) {
        check_update_cb(mender, merr);
        return;
    }
}

static mender_err_t mender_fetchupdate_on_init_success(void *ctx) {
    struct mender *mender = ctx;
    mender_err_t merr;

    merr = mender_installer_begin(&mender->installer, mender->new_artifact_name);
    if (merr) {
        LOGE("Can't begin installation: %08x", merr);
        return merr;
    }

    return MERR_NONE;
}

static void mender_fetchupdate_on_finish(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;
    mender_err_t merr;
    mender_err_t cbret;

    if (err) {
        cbret = err;
        goto do_callback;
    }

    merr = mender_installer_finish(&mender->installer);
    if (merr) {
        LOGE("Can't finish installation: %08x", merr);
        cbret = merr;
        goto do_callback;
    }

    cbret = MERR_NONE;

do_callback:
    if (mender->cb) {
        mender_on_result_t cb = mender->cb;
        void *cbctx = mender->cbctx;

        mender->cb = NULL;
        mender->cbctx = NULL;

        cb(cbctx, cbret);
    }
    else {
        LOGW("no callback set");
    }
}

static mender_err_t mender_fetchupdate_on_data(void *ctx, const void *data, size_t len) {
    struct mender *mender = ctx;
    mender_err_t merr;

    merr = mender_installer_process_data(&mender->installer, data, len);
    if (merr) {
        LOGE("Can't process installation data: %08x", merr);
        return merr;
    }

    return MERR_NONE;
}

void mender_fetch_update(struct mender *mender, const char *url, const char *artifact_name, mender_on_result_t cb, void *cbctx) {
    mender_err_t merr;

    if (mender->cb) {
        LOGE("another request is already running");
        cb(cbctx, MERR_BUSY);
        return;
    }

    mender->cb = cb;
    mender->cbctx = cbctx;

    mender->new_artifact_name = artifact_name;
    merr = mender_client_update_fetch(&mender->client_update, url, mender_get_retry_poll_interval(mender),
        &mender->fetch_update_cb, mender);
    if (merr) {
        LOGE("update fetch failed: %08x", merr);
        mender->cb = NULL;
        mender->cbctx = NULL;
        cb(cbctx, merr);
        return;
    }
}

static void mender_client_status_cb(void *ctx, mender_err_t err);

static void report_status_reauth_cb(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;
    mender_err_t merr;

    if (err) {
        LOGW("Reauthorization failed with error: %08x", err);
        mender_client_status_cb(mender, MERR_CLIENT_UNAUTHORIZED);
    }
    else {
        merr = mender_client_status_report(&mender->client_status,
            mender->server_url, mender->reportstatus_updateid,
            mender->reportstatus_status, mender_client_status_cb, mender);
        if (merr) {
            mender_client_status_cb(mender, merr);
            return;
        }
    }
}

static void mender_client_status_cb(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;
    mender_err_t cbret;

    if (err) {
        LOGE("error reporting update status: %08x", err);

        /* remove authentication token if device is not authorized */
        if (MENDER_ERR_VAL(err) == MERR_CLIENT_UNAUTHORIZED) {
            if (mender_authmgr_remove_auth_token(mender->authmgr)) {
                LOGW("can not remove rejected authentication token");
            }

            if (mender->nattempts == 0) {
                LOGI("Device unauthorized; attempting reauthorization");

                mender->nattempts++;
                mender_authorize(mender, report_status_reauth_cb, mender);
                return;
            }

            cbret = err;
        }
        else if (MENDER_ERR_VAL(err) == MERR_DEPLOYMENT_ABORTED) {
            cbret = MENDER_ERR_FATAL(err);
        }
        else {
            cbret = err;
        }
    }
    else {
        cbret = MERR_NONE;
    }

    if (mender->cb) {
        mender_on_result_t cb = mender->cb;
        void *cbctx = mender->cbctx;

        mender->cb = NULL;
        mender->cbctx = NULL;
        mender->nattempts = 0;

        cb(cbctx, cbret);
    }
    else {
        LOGW("no callback set");
    }
}

void mender_report_update_status(struct mender *mender, const char *updateid, enum mender_deployment_status status,
        mender_on_result_t cb, void *cbctx)
{
    mender_err_t merr;

    if (!updateid) {
        cb(cbctx, MERR_INVALID_ARGUMENTS);
        return;
    }

    mender->cb = cb;
    mender->cbctx = cbctx;
    mender->reportstatus_updateid = updateid;
    mender->reportstatus_status = status;
    mender->nattempts = 0;

    merr = mender_client_status_report(&mender->client_status,
        mender->server_url, updateid, status, mender_client_status_cb, mender);
    if (merr) {
        mender_client_status_cb(mender, merr);
        return;
    }
}

static void mender_client_log_cb(void *ctx, mender_err_t err);

static void upload_log_reauth_cb(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;
    mender_err_t merr;

    if (err) {
        LOGW("Reauthorization failed with error: %08x", err);
        mender_client_log_cb(mender, MERR_CLIENT_UNAUTHORIZED);
    }
    else {
        merr = mender_client_log_upload(&mender->client_log,
            mender->server_url, mender->reportstatus_updateid, mender->deployment_logs,
            mender_client_log_cb, mender);
        if (merr) {
            mender_client_log_cb(mender, merr);
            return;
        }
    }
}

static void mender_client_log_cb(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;
    mender_err_t cbret;

    if (err) {
        LOGE("error reporting update status: %08x", err);

        /* remove authentication token if device is not authorized */
        if (MENDER_ERR_VAL(err) == MERR_CLIENT_UNAUTHORIZED) {
            if (mender_authmgr_remove_auth_token(mender->authmgr)) {
                LOGW("can not remove rejected authentication token");
            }

            if (mender->nattempts == 0) {
                LOGI("Device unauthorized; attempting reauthorization");

                mender->nattempts++;
                mender_authorize(mender, upload_log_reauth_cb, mender);
                return;
            }

            cbret = err;
        }
        else if (MENDER_ERR_VAL(err) == MERR_DEPLOYMENT_ABORTED) {
            cbret = MENDER_ERR_FATAL(err);
        }
        else {
            cbret = err;
        }
    }
    else {
        cbret = MERR_NONE;
    }

    if (mender->cb) {
        mender_on_result_t cb = mender->cb;
        void *cbctx = mender->cbctx;

        mender->cb = NULL;
        mender->cbctx = NULL;
        mender->nattempts = 0;

        cb(cbctx, cbret);
    }
    else {
        LOGW("no callback set");
    }
}

void mender_upload_log(struct mender *mender,
        const char *updateid, const char *logs,
        mender_on_result_t cb, void *cbctx)
{
    mender_err_t merr;

    if (!updateid) {
        cb(cbctx, MERR_INVALID_ARGUMENTS);
        return;
    }

    mender->cb = cb;
    mender->cbctx = cbctx;
    mender->reportstatus_updateid = updateid;
    mender->nattempts = 0;
    mender->deployment_logs = logs;

    merr = mender_client_log_upload(&mender->client_log,
        mender->server_url, updateid, logs, mender_client_log_cb, mender);
    if (merr) {
        mender_client_log_cb(mender, merr);
        return;
    }
}

static void mender_inventory_refresh_cb(void *ctx, mender_err_t err);

static void inventory_refresh_do_send(struct mender *mender) {
    int rc;
    char *buf;
    size_t nbytes;
    size_t max;
    size_t actual;
    mender_err_t merr;
    struct mender_http_client *client = mender->httpclient;

    buf = mender_httpbuf_current(client);
    max = mender_httpbuf_num_free(client);
    rc = snprintf(buf, max,
        "["
        "{\"name\":\"device_type\", \"value\":\"%s\"},"
        "{\"name\":\"artifact_name\", \"value\":\"%s\"},"
        "{\"name\":\"mender_client_version\", \"value\":\""MENDER_VERSION_STR"\"}",
        mender->device_type, mender->current_artifact_name
    );
    if (rc < 0 || (size_t)rc >= max || mender_httpbuf_take(client, (size_t)rc) != buf) {
        LOGE("can't build inventory data");
        mender_inventory_refresh_cb(mender, MERR_OUT_OF_RESOURCES);
        return;
    }
    nbytes = (size_t)rc;

    merr = mender_inventory_data_write(mender->ivdata, mender_httpbuf_current(client),
        mender_httpbuf_num_free(client), &actual);
    if (merr || mender_httpbuf_take(client, actual) != buf + nbytes) {
        LOGE("mender_identity_data_write failed");
        mender_inventory_refresh_cb(mender, merr?:MERR_OUT_OF_RESOURCES);
        return;
    }
    nbytes += actual;

    if (mender_httpbuf_take(client, 1) != buf + nbytes) {
        LOGE("mender_httpbuf_take failed");
        mender_inventory_refresh_cb(mender, MERR_OUT_OF_RESOURCES);
        return;
    }
    buf[nbytes] = ']';
    nbytes++;

    merr = mender_client_inventory_submit(&mender->client_inventory,
        mender->server_url, buf, nbytes, mender_inventory_refresh_cb, mender);
    if (merr) {
        LOGE("inventory submission failed: %08x", merr);
        mender_inventory_refresh_cb(mender, merr);
        return;
    }
}

static void inventory_refresh_reauth_cb(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;

    if (err) {
        LOGW("Reauthorization failed with error: %08x", err);
        mender_inventory_refresh_cb(mender, MERR_CLIENT_UNAUTHORIZED);
    }
    else {
        inventory_refresh_do_send(mender);
    }
}

static void mender_inventory_refresh_cb(void *ctx, mender_err_t err) {
    struct mender *mender = ctx;

    if (err) {
        if (MENDER_ERR_VAL(err) == MERR_CLIENT_UNAUTHORIZED) {
            if (mender_authmgr_remove_auth_token(mender->authmgr)) {
                LOGW("can not remove rejected authentication token");
            }

            if (mender->nattempts == 0) {
                LOGI("Device unauthorized; attempting reauthorization");

                mender->nattempts++;
                mender_authorize(mender, inventory_refresh_reauth_cb, mender);
                return;
            }
        }
    }

    if (mender->cb) {
        mender_on_result_t cb = mender->cb;
        void *cbctx = mender->cbctx;

        mender->cb = NULL;
        mender->cbctx = NULL;
        mender->nattempts = 0;

        cb(cbctx, err);
    }
    else {
        LOGW("no callback set");
    }
}

void mender_inventory_refresh(struct mender *mender, mender_on_result_t cb, void *cbctx) {
    mender->cb = cb;
    mender->cbctx = cbctx;
    mender->nattempts = 0;

    inventory_refresh_do_send(mender);
}


/* UInstaller */
mender_err_t mender_enable_updated_partition(struct mender *mender) {
    struct mender_device *device = mender->device;

    return mender_device_enable_updated_partition(device);
}


/* UInstallCommitRebooter */
mender_err_t mender_commit_update(struct mender *mender) {
    struct mender_device *device = mender->device;

    return mender_device_commit_update(device);
}

mender_err_t mender_reboot(struct mender *mender) {
    struct mender_device *device = mender->device;

    return mender_device_reboot(device);
}

mender_err_t mender_swap_partitions(struct mender *mender) {
    struct mender_device *device = mender->device;

    return mender_device_swap_partitions(device);
}

mender_err_t mender_has_update(struct mender *mender, bool *phasupdate) {
    struct mender_device *device = mender->device;

    return mender_device_has_update(device, phasupdate);
}

void mender_create(struct mender *mender, struct mender_store *store, struct mender_authmgr *authmgr,
        struct mender_stack *stack, struct mender_http_client *httpclient, struct mender_device *device,
        struct mender_inventory_data *ivdata,
        const char *current_artifact_name, const char *device_type, const char *server_url,
        mender_duration_t update_poll_interval, mender_get_scheduled_time_t get_update_check_time_cb,
        mender_duration_t inventory_poll_interval, mender_duration_t retry_poll_interval)
{
    memset(mender, 0, sizeof(*mender));

    mender->store = store;
    mender->authmgr = authmgr;
    mender->stack = stack;
    mender->httpclient = httpclient;
    mender->device = device;
    mender->ivdata = ivdata;
    mender->current_artifact_name = current_artifact_name;
    mender->device_type = device_type;
    mender->server_url = server_url;
    mender->update_poll_interval = update_poll_interval;
    mender->get_update_check_time = get_update_check_time_cb;
    mender->inventory_poll_interval = inventory_poll_interval;
    mender->retry_poll_interval = retry_poll_interval;

    mender_client_auth_create(&mender->client_auth, httpclient, authmgr);
    mender_client_inventory_create(&mender->client_inventory, httpclient, authmgr);
    mender_client_update_create(&mender->client_update, httpclient, authmgr);
    mender_client_status_create(&mender->client_status, httpclient, authmgr);
    mender_client_log_create(&mender->client_log, httpclient, authmgr);
    mender_installer_create(&mender->installer, mender->device, mender->stack, mender->device_type);

    mender->fetch_update_cb.on_init_success = mender_fetchupdate_on_init_success;
    mender->fetch_update_cb.on_finish = mender_fetchupdate_on_finish;
    mender->fetch_update_cb.on_data = mender_fetchupdate_on_data;
}

const char *mender_state_to_str(enum mender_state s) {
    switch (s) {
    case MENDER_STATE_INIT: return "MENDER_STATE_INIT";
    case MENDER_STATE_IDLE: return "MENDER_STATE_IDLE";
    case MENDER_STATE_AUTHORIZE: return "MENDER_STATE_AUTHORIZE";
    case MENDER_STATE_AUTHORIZE_ASYNC: return "MENDER_STATE_AUTHORIZE_ASYNC";
    case MENDER_STATE_AUTHORIZE_WAIT: return "MENDER_STATE_AUTHORIZE_WAIT";
    case MENDER_STATE_INVENTORY_UPDATE: return "MENDER_STATE_INVENTORY_UPDATE";
    case MENDER_STATE_INVENTORY_UPDATE_ASYNC: return "MENDER_STATE_INVENTORY_UPDATE_ASYNC";
    case MENDER_STATE_CHECK_WAIT: return "MENDER_STATE_CHECK_WAIT";
    case MENDER_STATE_UPDATE_CHECK: return "MENDER_STATE_UPDATE_CHECK";
    case MENDER_STATE_UPDATE_CHECK_ASYNC: return "MENDER_STATE_UPDATE_CHECK_ASYNC";
    case MENDER_STATE_UPDATE_FETCH: return "MENDER_STATE_UPDATE_FETCH";
    case MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC: return "MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC";
    case MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC: return "MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC";
    case MENDER_STATE_UPDATE_STORE: return "MENDER_STATE_UPDATE_STORE";
    case MENDER_STATE_UPDATE_STORE_ASYNC_REPORT: return "MENDER_STATE_UPDATE_STORE_ASYNC_REPORT";
    case MENDER_STATE_UPDATE_INSTALL: return "MENDER_STATE_UPDATE_INSTALL";
    case MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT: return "MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT";
    case MENDER_STATE_FETCH_STORE_RETRY_WAIT: return "MENDER_STATE_FETCH_STORE_RETRY_WAIT";
    case MENDER_STATE_UPDATE_VERIFY: return "MENDER_STATE_UPDATE_VERIFY";
    case MENDER_STATE_UPDATE_COMMIT: return "MENDER_STATE_UPDATE_COMMIT";
    case MENDER_STATE_UPDATE_STATUS_REPORT: return "MENDER_STATE_UPDATE_STATUS_REPORT";
    case MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT: return "MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT";
    case MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC: return "MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC";
    case MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS: return "MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS";
    case MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS_ASYNC: return "MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS_ASYNC";
    case MENDER_STATE_UPDATE_STATUS_REPORT_COMPLETE: return "MENDER_STATE_UPDATE_STATUS_REPORT_COMPLETE";
    case MENDER_STATE_STATUS_REPORT_RETRY: return "MENDER_STATE_STATUS_REPORT_RETRY";
    case MENDER_STATE_REPORT_STATUS_ERROR: return "MENDER_STATE_REPORT_STATUS_ERROR";
    case MENDER_STATE_REBOOT: return "MENDER_STATE_REBOOT";
    case MENDER_STATE_REBOOT_ASYNC_REPORT: return "MENDER_STATE_REBOOT_ASYNC_REPORT";
    case MENDER_STATE_AFTER_REBOOT: return "MENDER_STATE_AFTER_REBOOT";
    case MENDER_STATE_ROLLBACK: return "MENDER_STATE_ROLLBACK";
    case MENDER_STATE_ROLLBACK_REBOOT: return "MENDER_STATE_ROLLBACK_REBOOT";
    case MENDER_STATE_AFTER_ROLLBACK_REBOOT: return "MENDER_STATE_AFTER_ROLLBACK_REBOOT";
    case MENDER_STATE_ERROR: return "MENDER_STATE_ERROR";
    case MENDER_STATE_UPDATE_ERROR: return "MENDER_STATE_UPDATE_ERROR";
    case MENDER_STATE_DONE: return "MENDER_STATE_DONE";
    default: return "unknown";
    }
}
