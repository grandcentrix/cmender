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

#ifndef MENDER_MENDER_H
#define MENDER_MENDER_H

#include <mender/client.h>
#include <mender/error.h>
#include <mender/platform/types.h>
#include <mender/authmgr.h>
#include <mender/http.h>
#include <mender/client_auth.h>
#include <mender/client_inventory.h>
#include <mender/client_update.h>
#include <mender/client_status.h>
#include <mender/client_log.h>
#include <mender/installer.h>
#include <mender/device.h>
#include <mender/inventory_data.h>

enum mender_state {
    /* initial state */
    MENDER_STATE_INIT = 0,
    /* idle state; waiting for transition to the new state */
    MENDER_STATE_IDLE,
    /* client is bootstrapped, i.e. ready to go */
    MENDER_STATE_AUTHORIZE,
    MENDER_STATE_AUTHORIZE_ASYNC,
    /* wait before authorization attempt */
    MENDER_STATE_AUTHORIZE_WAIT,
    /* inventory update */
    MENDER_STATE_INVENTORY_UPDATE,
    MENDER_STATE_INVENTORY_UPDATE_ASYNC,
    /* wait for new update or inventory sending */
    MENDER_STATE_CHECK_WAIT,
    /* check update */
    MENDER_STATE_UPDATE_CHECK,
    MENDER_STATE_UPDATE_CHECK_ASYNC,
    /* update fetch */
    MENDER_STATE_UPDATE_FETCH,
    MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC,
    MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC,
    /* update store */
    MENDER_STATE_UPDATE_STORE,
    MENDER_STATE_UPDATE_STORE_ASYNC_REPORT,
    /* install update */
    MENDER_STATE_UPDATE_INSTALL,
    MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT,
    /*
     * wait before retrying fetch & install after first failing (timeout,
     * for example)
     */
    MENDER_STATE_FETCH_STORE_RETRY_WAIT,
    /* varify update */
    MENDER_STATE_UPDATE_VERIFY,
    /* commit needed */
    MENDER_STATE_UPDATE_COMMIT,
    /* status report */
    MENDER_STATE_UPDATE_STATUS_REPORT,
    MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT,
    MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC,
    MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS,
    MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS_ASYNC,
    MENDER_STATE_UPDATE_STATUS_REPORT_COMPLETE,
    /* wait before retrying sending either report or deployment logs */
    MENDER_STATE_STATUS_REPORT_RETRY,
    /* error reporting status */
    MENDER_STATE_REPORT_STATUS_ERROR,
    /* reboot */
    MENDER_STATE_REBOOT,
    MENDER_STATE_REBOOT_ASYNC_REPORT,
    /* first state after booting device after rollback reboot */
    MENDER_STATE_AFTER_REBOOT,
    /* rollback */
    MENDER_STATE_ROLLBACK,
    /* reboot after rollback */
    MENDER_STATE_ROLLBACK_REBOOT,
    /* first state after booting device after rollback reboot */
    MENDER_STATE_AFTER_ROLLBACK_REBOOT,
    /* error */
    MENDER_STATE_ERROR,
    /* update error */
    MENDER_STATE_UPDATE_ERROR,
    /* exit state */
    MENDER_STATE_DONE
};

typedef void (*mender_on_result_t)(void *ctx, mender_err_t err);

struct mender {
    struct mender_store *store;
    struct mender_authmgr *authmgr;
    struct mender_stack *stack;
    struct mender_http_client *httpclient;
    struct mender_device *device;
    struct mender_inventory_data *ivdata;

    struct mender_client_auth client_auth;
    struct mender_client_inventory client_inventory;
    struct mender_client_update client_update;
    struct mender_client_log client_log;
    struct mender_client_status client_status;
    struct mender_installer installer;
    const char *current_artifact_name;
    const char *device_type;
    const char *server_url;
    mender_duration_t update_poll_interval;
    mender_duration_t inventory_poll_interval;
    mender_duration_t retry_poll_interval;

    const char *new_artifact_name;

    size_t nattempts;

    bool force_bootstrap;
    struct mender_client_update_fetch_cb fetch_update_cb;

    mender_on_result_t cb;
    void *cbctx;

    mender_on_result_t auth_cb;
    void *auth_cbctx;

    struct mender_update_response *check_ur;

    const char *reportstatus_updateid;
    enum mender_deployment_status reportstatus_status;
    const char *deployment_logs;
};

const char *mender_state_to_str(enum mender_state s);
void mender_create(struct mender *mender, struct mender_store *store, struct mender_authmgr *authmgr,
        struct mender_stack *stack, struct mender_http_client *httpclient, struct mender_device *device,
        struct mender_inventory_data *ivdata,
        const char *current_artifact_name, const char *device_type, const char *server_url,
        mender_duration_t update_poll_interval, mender_duration_t inventory_poll_interval,
        mender_duration_t retry_poll_interval);

/* Controller */
bool mender_is_authorized(struct mender *mender);
void mender_authorize(struct mender *mender, mender_on_result_t cb, void *cbctx);
mender_err_t mender_get_current_artifact_name(struct mender *mender, const char **pname);
mender_duration_t mender_get_update_poll_interval(struct mender *mender);
mender_duration_t mender_get_inventory_poll_interval(struct mender *mender);
mender_duration_t mender_get_retry_poll_interval(struct mender *mender);
mender_err_t mender_has_upgrade(struct mender *mender, bool *phasupgrade);
void mender_check_update(struct mender *mender, struct mender_update_response *ur, mender_on_result_t cb, void *cbctx);
void mender_fetch_update(struct mender *mender, const char *url, const char *artifact_name, mender_on_result_t cb, void *cbctx);
void mender_report_update_status(struct mender *mender, const char *updateid, enum mender_deployment_status status,
    mender_on_result_t cb, void *cbctx);
void mender_upload_log(struct mender *mender, const char *updateid, const char *logs,
    mender_on_result_t cb, void *cbctx);
void mender_inventory_refresh(struct mender *mender, mender_on_result_t cb, void *cbctx);

/* UInstaller */
mender_err_t mender_enable_updated_partition(struct mender *mender);

/* UInstallCommitRebooter */
mender_err_t mender_commit_update(struct mender *mender);
mender_err_t mender_reboot(struct mender *mender);
mender_err_t mender_swap_partitions(struct mender *mender);
mender_err_t mender_has_update(struct mender *mender, bool *phasupdate);

#endif /* MENDER_MENDER_H */
