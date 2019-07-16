/*
 * Copyright 2018 Northern.tech AS
 * Copyright 2019 grandcentrix GmbH
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <mender/state.h>
#include <mender/platform/log.h>
#include <mender/deployment_logger.h>
#include <mender/client.h>
#include <mender/mender.h>
#include <mender/internal/compiler.h>
#include <mender/hexdump.h>

#ifdef MENDER_ENABLE_TESTING
#include <mender/test/mock/store.h>
#include <mender/test/mock/mender.h>
#include <mender/test/mock/time.h>
#endif

/*
 * Each state implements Handle() - a state handler method that performs actions
 * on the Controller. The handler returns a new state, thus performing a state
 * transition. Each state can transition to an instance of ErrorState (or
 * UpdateErrorState for update related states). The handling of error states is
 * described further down.
 *
 * Regular state transitions:
 *
 *                               init
 *
 *                                 |        (wait timeout expired)
 *                                 |   +---------------------------------+
 *                                 |   |                                 |
 *                                 v   v                                 |
 *                                           (auth req. failed)
 *                            bootstrapped ----------------------> authorize wait
 *
 *                                  |
 *                                  |
 *                                  |  (auth data avail.)
 *                                  |
 *                                  v
 *
 *                             authorized
 *
 *            (update needs     |   |
 *             verify)          |   |
 *           +------------------+   |
 *           |                      |
 *           v                      |
 *                                  |
 *     update verify                |
 *                                  |
 *      |        |                  |
 * (ok) |        | (update error)   |
 *      |        |                  |
 *      v        v                  |
 *                                  |
 *   update    update               |           (wait timeout expired)
 *   commit    report state         |    +-----------------------------+
 *                                  |    |                             |
 *      |         |                 |    |                             |
 *      +----+----+                 v    v                             |
 *           |                                (no update)
 *           +---------------> update check ---------------->  update check wait
 *
 *                                  |
 *                                  | (update ready)
 *                                  |
 *                                  |   +-----------------------------+
 *                                  |   |                             |
 *                                  v   v                             |
 *
 *                             update fetch ------------------> retry update
 *
 *                                  |                                 ^
 *                                  | (update fetched)                |
 *                                  v                                 |
 *                                                                    |
 *                            update install -------------------------+
 *
 *                                  |
 *                                  | (update installed,
 *                                  |  enabled)
 *                                  |
 *                                  v
 *
 *                                reboot
 *
 *                                  |
 *                                  v
 *
 *                                final (daemon exit)
 *
 * Errors and their context are captured in Error states. Non-update states
 * transition to an ErrorState, while update related states (fetch, install,
 * commit) transition to UpdateErrorState that captures additional update
 * context information. Error states implement IsFatal() method to check whether
 * the cause is fatal or not.
 *
 *        +------------------> init <-----------------------+
 *        |                                                 |
 *        |                      |                          |
 *        |                      |                          |
 *        |                      |                          |
 *        |                      v                          |
 *                                             (bootstrap)  |
 *   error state <--------- non-update states  (authorized) |
 *                                             (* wait)     |
 *        |                       ^            (check)      |
 *        |                       |                         |
 *        |                       |                         |
 *        |                       |                         |
 *        |      (fetch  )        v                         |
 *        |      (install)
 *        |      (enable )  update states ---------> update error state
 *        |      (verify )
 *        |      (commit )        |                         |
 *        |      (report )        |                         |
 *        |      (reboot )        |                         |
 *        |                       |                         |
 *        |                       v                         |
 *        |                                                 |
 *        +-------------------> final <---------------------+
 *                           (daemon exit)
 *
 */

/* name of key that state data is stored under across reboots */
static const char *state_data_key = "state";

/*
 * current version of the format of StateData;
 * incerease the version number once the format of struct mender_statedata is changed
 */
static const int state_data_version = 1;

static mender_err_t store_state_data(struct mender_store *store, struct mender_statedata *sd){
    /* if the verions is not filled in, use the current one */
    if (sd->version == 0) {
        sd->version = state_data_version;
    }

    return mender_store_write_all(store, state_data_key, sd, sizeof(*sd));
}

static mender_err_t load_state_data(struct mender_store *store, struct mender_statedata *pstatedata) {
    mender_err_t err;
    struct mender_statedata sd;
    size_t actual;

    err = mender_store_read_all(store, state_data_key, &sd, sizeof(sd), &actual);
    if (err || actual != sizeof(sd)) {
        return err;
    }

    switch (sd.version) {
    case 0:
    case 1:
        *pstatedata = sd;
        return MERR_NONE;
    default:
        return MERR_UNSUPPORTED_STATE_DATA;
    }
}

static void init_state_data(struct mender_statemachine *sm, enum mender_deployment_status status) {
    memset(&sm->sd, 0, sizeof(sm->sd));
    sm->sd.version = 0;
    sm->sd.state = sm->current_state;
    memcpy(sm->sd.artifact_name, sm->update.artifact_name, sizeof(sm->sd.artifact_name));
    memcpy(sm->sd.id, sm->update.id, sizeof(sm->sd.id));
    sm->sd.deployment_status = status;
}

static mender_err_t remove_state_data(struct mender_store *store) {
    if (store == NULL) {
        return MERR_NONE;
    }
    return mender_store_remove(store, state_data_key);
}

static void on_mender_result(void *ctx, mender_err_t err) {
    struct mender_statemachine *sm = ctx;

    sm->next_state_update = 0;
    sm->last_error = err;
}

static void idle_state_handle(struct mender_statemachine *sm) {
    /* stop deployment logging */
    deployment_logger_disable();

    /* cleanup state-data if any data is still present after an update */
    remove_state_data(sm->store);

    /* check if client is authorized */
    if (mender_is_authorized(sm->mender)) {
        sm->current_state = MENDER_STATE_CHECK_WAIT;
        return;
    }

    sm->current_state = MENDER_STATE_AUTHORIZE;
}

static bool committed_partition(struct mender *mender) {
    bool ua;
    mender_err_t err;

    err = mender_has_upgrade(mender, &ua);
    if (err) {
        /* failure to query u-boot */
        return false;
    }
    return !ua;
}

static void import_update_from_state(struct mender_statemachine *sm) {
    memset(&sm->update, 0, sizeof(sm->update));
    memcpy(sm->update.artifact_name, &sm->sd.artifact_name, sizeof(sm->update.artifact_name));
    memcpy(sm->update.id, &sm->sd.id, sizeof(sm->update.id));
}

static void init_state_handle(struct mender_statemachine *sm) {
    mender_err_t err;

    /* restore previous state information */
    err = load_state_data(sm->store, &sm->sd);

    /*
     * handle easy case first: no previous state stored,
     * means no update was in progress; we should continue from idle
     */
    if (err && MENDER_ERR_VAL(err) == MERR_NOT_FOUND) {
        LOGD("no state data stored");
        sm->current_state = MENDER_STATE_IDLE;
        return;
    }

    if (err) {
        LOGE("failed to restore state data: %08x", err);
        sm->last_error = MERR_FAILED_TO_RESTORE_STATE_DATA;
        sm->current_state = MENDER_STATE_UPDATE_ERROR;
        return;
    }

    LOGI("handling loaded state: %s(%u)", mender_state_to_str(sm->sd.state), sm->sd.state);

    if (!committed_partition(sm->mender)) {
        /* only valid entrypoint into the uncommitted partition is reboot_leave */
        if (sm->sd.state != MENDER_STATE_REBOOT) {
            /*
             * entered the uncommitted partition without finishing the whole update-path
             * on the committed partition, therefore reboot back into the committed partition
             * and error
             * XXX: this relies on the bootloader to check the bootcount
             *      and clear the upgrade_available variable
             */
            LOGI("Entered the uncommitted partition with invalid state-data stored. Rebooting.");
            err = mender_reboot(sm->mender);
            if (err) {
                import_update_from_state(sm);
                sm->last_error = MENDER_ERR_FATAL(MERR_REBOOT_FAILED);
                sm->current_state = MENDER_STATE_UPDATE_ERROR;
                return;
            }
            /* should never happen */
            sm->current_state = MENDER_STATE_DONE;
            return;
        }
        import_update_from_state(sm);
        sm->current_state = MENDER_STATE_AFTER_REBOOT;
        return;
    }

    /* check last known state */
    switch (sm->sd.state) {

    case MENDER_STATE_ROLLBACK_REBOOT:
        import_update_from_state(sm);
        sm->current_state = MENDER_STATE_AFTER_ROLLBACK_REBOOT;
        return;

    /* Rerun commit-leave */
    case MENDER_STATE_UPDATE_COMMIT: {
        sm->current_state = MENDER_STATE_IDLE;
        return;
    }

    /* invalid entrypoint into the state-machine. Error out. */
    default:
        err = deployment_logger_enable(sm->sd.id);
        if (err) {
            /* just log error */
            LOGE("failed to enable deployment logger: %08x", err);
        }
        LOGE("got invalid entrypoint into the state machine: state: %s(%u)",
            mender_state_to_str(sm->sd.state), sm->sd.state);

        sm->last_error = MERR_INVALID_STATE_STORED;
        import_update_from_state(sm);
        sm->current_state = MENDER_STATE_UPDATE_ERROR;
        return;
    }
}

static void authorize_state_handle(struct mender_statemachine *sm) {
    /* stop deployment logging */
    deployment_logger_disable();

    LOGD("handle authorize state");
    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_AUTHORIZE_ASYNC;
    mender_authorize(sm->mender, on_mender_result, sm);
}

static void authorize_async_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err) {
        LOGE("authorize failed: %08x", err);

        if (MENDER_ERR_ISFATAL(err)) {
            sm->current_state = MENDER_STATE_ERROR;
        }
        else {
            sm->current_state = MENDER_STATE_AUTHORIZE_WAIT;
        }

        return;
    }

    /*
     * if everything is OK we should let Mender figure out what to do
     * in MENDER_STATE_CHECK_WAIT state
     */
    sm->current_state = MENDER_STATE_CHECK_WAIT;
}

static void authorize_wait_state_handle(struct mender_statemachine *sm) {
    mender_duration_t intvl;

    LOGD("handle authorize wait state");
    intvl = mender_get_retry_poll_interval(sm->mender);

    LOGD("wait %llu before next authorization attempt", (unsigned long long)intvl);
    sm->next_state_update = mender_time_now() + intvl;
    sm->current_state = MENDER_STATE_AUTHORIZE;
}

static void update_verify_state_handle(struct mender_statemachine *sm) {
    bool has;
    mender_err_t err;
    mender_err_t haserr;

    /* start deployment logging */
    err = deployment_logger_enable(sm->update.id);
    if (err) {
        /* just log error */
        LOGE("failed to enable deployment logger: %08x", err);
    }

    LOGD("handle update verify state");

    /* look at the update flag */
    haserr = mender_has_upgrade(sm->mender, &has);
    if (haserr) {
        LOGE("has upgrade check failed: %08x", haserr);
        sm->last_error = MERR_FAILED_TO_PERFORM_UPGRADE_CHECK;
        sm->current_state = MENDER_STATE_UPDATE_ERROR;
        return;
    }

    if (has) {
        sm->current_state = MENDER_STATE_UPDATE_COMMIT;
        return;
    }

    /*
     * HasUpgrade() returned false
     * most probably booting new image failed and u-boot rolled back to
     * previous image
     */
    LOGE("update info for deployment %s present, but update flag is not set;"
        " running rollback image (previous active partition)",
        sm->update.id);

    sm->rollback_state.swap = false;
    sm->rollback_state.reboot = false;
    sm->current_state = MENDER_STATE_ROLLBACK;
}

static void update_commit_state_handle(struct mender_statemachine *sm) {
    const char *artifact_name;
    mender_err_t err;

    /* start deployment logging */
    err = deployment_logger_enable(sm->update.id);
    if (err) {
        LOGE("Can not enable deployment logger: %08x", err);
    }

    LOGD("handle update commit state");

    err = mender_get_current_artifact_name(sm->mender, &artifact_name);
    if (err) {
        LOGE("Cannot determine name of new artifact. Update will not continue: %08x", err);
        sm->rollback_state.swap = false;
        sm->rollback_state.reboot = true;
        sm->current_state = MENDER_STATE_ROLLBACK;
        return;
    } else if (strcmp(sm->update.artifact_name, artifact_name)) {
        /*
         * seems like we're running in a different image than expected from update
         * information, best report an error
         * this can ONLY happen if the artifact name does not match information
         * stored in `/etc/mender/artifact_info` file
         */
        LOGE("running with image %s, expected updated image %s",
            artifact_name, sm->update.artifact_name);

        sm->rollback_state.swap = false;
        sm->rollback_state.reboot = true;
        sm->current_state = MENDER_STATE_ROLLBACK;
        return;
    }

    /*
     * update info and has upgrade flag are there, we're running the new
     * update, everything looks good, proceed with committing
     */
    LOGI("successfully running with new image %s", artifact_name);

    err = mender_commit_update(sm->mender);
    if (err) {
        LOGE("update commit failed: %08x", err);
        /*
         * we need to perform roll-back here; one scenario is when u-boot fw utils
         * won't work after update; at this point without rolling-back it won't be
         * possible to perform new update
         */
        sm->rollback_state.swap = false;
        sm->rollback_state.reboot = true;
        sm->current_state = MENDER_STATE_ROLLBACK;
        return;
    }

    LOGI("Storing commit state data");
    init_state_data(sm, MENDER_DEPLOYMENT_STATUS_INVALID);
    err = store_state_data(sm->store, &sm->sd);
    if (err) {
        /* The update is already committed, so not much we can do */
        LOGE("failed to write state-data to storage: %08x", err);
    }

    /* update is commited now; report status */
    sm->deployment_status = MENDER_DEPLOYMENT_STATUS_SUCCESS;
    sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
}

static void update_check_state_handle(struct mender_statemachine *sm) {
    LOGD("handle update check state");
    sm->last_update_check = mender_time_now();

    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_UPDATE_CHECK_ASYNC;
    mender_check_update(sm->mender, &sm->update, on_mender_result, sm);
}

static void update_check_async_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err) {
        if (MENDER_ERR_VAL(err) == MERR_EXISTS) {
            /*
             * We are already running image which we are supposed to install.
             * Just report successful update and return to normal operations.
             */
            sm->deployment_status = MENDER_DEPLOYMENT_STATUS_ALREADY_INSTALLED;
            sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
            return;
        }

        if (MENDER_ERR_VAL(err) == MERR_NOT_FOUND) {
            sm->current_state = MENDER_STATE_CHECK_WAIT;
            return;
        }

        LOGE("update check failed: %08x", err);
        sm->current_state = MENDER_STATE_ERROR;
        return;
    }

    sm->current_state = MENDER_STATE_UPDATE_FETCH;
}

static void update_fetch_state_handle(struct mender_statemachine *sm) {
    mender_err_t merr;

    /* start deployment logging */
    merr = deployment_logger_enable(sm->update.id);
    if (merr) {
        sm->deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
        sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
        return;
    }

    LOGD("handle update fetch state");
    init_state_data(sm, MENDER_DEPLOYMENT_STATUS_INVALID);
    merr = store_state_data(sm->store, &sm->sd);
    if (merr) {
        LOGE("failed to store state data in fetch state: %08x", merr);
        sm->deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
        sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
        return;
    }

    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC;
    sm->deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    mender_report_update_status(sm->mender, sm->update.id,
        sm->deployment_status, on_mender_result, sm);
}

static void update_fetch_send_report_async_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err && MENDER_ERR_ISFATAL(err)) {
        sm->deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
        sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
        return;
    }

    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC;
    mender_fetch_update(sm->mender, sm->update.uri, sm->update.artifact_name, on_mender_result, sm);
}

static void update_fetch_send_dofetch_async_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err) {
        LOGE("update fetch failed: %08x", err);
        sm->current_state = MENDER_STATE_FETCH_STORE_RETRY_WAIT;
        return;
    }

    sm->current_state = MENDER_STATE_UPDATE_STORE;
}

static void update_store_state_handle(struct mender_statemachine *sm) {
    mender_err_t err;

    LOGD("handle update install state");
    init_state_data(sm, MENDER_DEPLOYMENT_STATUS_INVALID);
    err = store_state_data(sm->store, &sm->sd);
    if (err) {
        LOGE("failed to store state data in install state: %08x", err);
        sm->deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
        sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
        return;
    }

    /* restart counter so that we are able to retry next time */
    sm->fetch_install_attempts = 0;

    /*
     * check if update is not aborted
     * this step is needed as installing might take a while and we might end up with
     * proceeding with already cancelled update
     */
    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_UPDATE_STORE_ASYNC_REPORT;
    sm->deployment_status = MENDER_DEPLOYMENT_STATUS_DOWNLOADING;
    mender_report_update_status(sm->mender, sm->update.id,
        sm->deployment_status, on_mender_result, sm);
}

static void update_store_async_report_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err && MENDER_ERR_ISFATAL(err)) {
        sm->deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
        sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
        return;
    }

    sm->current_state = MENDER_STATE_UPDATE_INSTALL;
}

static void update_install_state_handle(struct mender_statemachine *sm) {
    mender_err_t err;

    /* start deployment logging */
    err = deployment_logger_enable(sm->update.id);
    if (err) {
        sm->deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
        sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
        return;
    }

    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT;
    sm->deployment_status = MENDER_DEPLOYMENT_STATUS_INSTALLING;
    mender_report_update_status(sm->mender, sm->update.id, sm->deployment_status, on_mender_result, sm);
}

static void update_install_async_report_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err && MENDER_ERR_ISFATAL(err)) {
        sm->last_error = MENDER_ERR_VAL(err);
        sm->current_state = MENDER_STATE_UPDATE_ERROR;
        return;
    }

    /* if install was successful mark inactive partition as active one */
    err = mender_enable_updated_partition(sm->mender);
    if (err) {
        sm->last_error = err;
        sm->current_state = MENDER_STATE_UPDATE_ERROR;
        return;
    }

    sm->current_state = MENDER_STATE_REBOOT;
}

static void fetch_store_retry_wait_state_handle(struct mender_statemachine *sm) {
    mender_duration_t intvl;
    mender_err_t err;

    LOGD("handle fetch install retry state");

    err = mender_client_get_exponential_backoff_time(sm->fetch_install_attempts,
        mender_get_update_poll_interval(sm->mender), &intvl);
    if (err) {
        if (sm->last_error) {
            sm->deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
            sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
            return;
        }
        sm->last_error = err;
        sm->current_state = MENDER_STATE_UPDATE_ERROR;
        return;
    }

    sm->fetch_install_attempts++;

    LOGD("wait %llu before next fetch/install attempt", (unsigned long long)intvl);

    sm->next_state_update = mender_time_now() + intvl;
    sm->current_state = MENDER_STATE_UPDATE_FETCH;
}

static void check_wait_state_handle(struct mender_statemachine *sm) {
    mender_time_t when;
    enum mender_state state;
    mender_time_t update;
    mender_time_t inventory;
    mender_time_t now;
    mender_time_t scheduled_update_check;

    LOGD("handle check wait state");

    scheduled_update_check = mender_get_scheduled_update_time(sm->mender);
    now = mender_time_now();

    /* calculate next interval */
    if (scheduled_update_check < now)
        update = sm->last_update_check + mender_get_update_poll_interval(sm->mender);
    else
        update = scheduled_update_check;
    inventory = sm->last_inventory_update + mender_get_inventory_poll_interval(sm->mender);

    /* if we haven't sent inventory so far */
    if (sm->last_inventory_update == 0) {
        inventory = sm->last_inventory_update;
    }

    LOGD("check wait state; next checks: (update: %llu) (inventory: %llu)",
        (unsigned long long)update, (unsigned long long)inventory);

    if (inventory < update) {
        when = inventory;
        state = MENDER_STATE_INVENTORY_UPDATE;
    }
    else {
        when = update;
        state = MENDER_STATE_UPDATE_CHECK;
    }

    LOGD("next check: %llu:%s, (%llu)", (unsigned long long)when,
            mender_state_to_str(state), (unsigned long long)now);

    /*
     * check if we should wait for the next state or we should return
     * immediately
     */
    if (when > now) {
        mender_time_t wait = when - now;
        LOGD("waiting %llu for the next state", (unsigned long long)wait);

        sm->next_state_update = when;
        sm->current_state = state;
        return;
    }

    LOGD("check wait returned: %s", mender_state_to_str(state));
    sm->current_state = state;
}

static void inventory_update_state_handle(struct mender_statemachine *sm) {
    sm->last_inventory_update = mender_time_now();

    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_INVENTORY_UPDATE_ASYNC;
    mender_inventory_refresh(sm->mender, on_mender_result, sm);
}

static void inventory_update_async_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err) {
        LOGW("failed to refresh inventory: %08x", err);
        if (MENDER_ERR_VAL(err) == MERR_NO_ARTIFACT_NAME) {
            sm->last_error = err;
            sm->current_state = MENDER_STATE_ERROR;
            return;
        }

    } else {
        LOGD("inventory refresh complete");
    }

    sm->current_state = MENDER_STATE_CHECK_WAIT;
}

static void error_state_handle(struct mender_statemachine *sm) {
    /* stop deployment logging */
    deployment_logger_disable();

    LOGI("handling error state, current error: %08x", sm->last_error);
    /* decide if error is transient, exit for now */
    if (MENDER_ERR_ISFATAL(sm->last_error)) {
        sm->current_state = MENDER_STATE_DONE;
        return;
    }
    sm->current_state = MENDER_STATE_IDLE;
}

static void update_error_state_handle(struct mender_statemachine *sm) {
    LOGD("handle update error state");

    deployment_logger_log(mender_state_to_str(sm->last_state), sm->last_state, sm->deployment_status, sm->last_error);

    sm->deployment_status = MENDER_DEPLOYMENT_STATUS_FAILURE;
    sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT;
}

static void update_status_report_state_handle(struct mender_statemachine *sm) {
    /*
     * start deployment logging; no error checking
     * we can do nothing here; either we will have the logs or not...
     */
    deployment_logger_enable(sm->update.id);

    LOGD("handle update status report state");

    /*
     * Do not store this if artifact-commit scripts are run when leaving the state
     * as then the scripts will not be rerun
     */
    if (sm->current_state != MENDER_STATE_UPDATE_COMMIT) {
        mender_err_t nerr;

        init_state_data(sm, sm->deployment_status);
        nerr = store_state_data(sm->store, &sm->sd);
        if (nerr) {
            LOGE("failed to store state data in update status report state: %08x", nerr);
            sm->current_state = MENDER_STATE_REPORT_STATUS_ERROR;
            return;
        }
    }

    memset(&sm->updatestatusreport_state, 0, sizeof(sm->updatestatusreport_state));
    sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT;
}

static void update_status_report_send_report_state_handle(struct mender_statemachine *sm) {
    sm->updatestatusreport_state.tries_sending_report++;

    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC;
    mender_report_update_status(sm->mender, sm->update.id, sm->deployment_status,
        on_mender_result, sm);
}

static void update_status_report_send_report_async_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err) {
        LOGE("failed to send status to server: %08x", err);
        if (MENDER_ERR_ISFATAL(err)) {
            sm->current_state = MENDER_STATE_REPORT_STATUS_ERROR;
            return;
        }

        sm->updatestatusreportretry_state.tries_sending = sm->updatestatusreport_state.tries_sending_report;
        sm->updatestatusreportretry_state.next_state = MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT;
        sm->current_state = MENDER_STATE_STATUS_REPORT_RETRY;
        return;
    }

    if (sm->deployment_status == MENDER_DEPLOYMENT_STATUS_FAILURE) {
        sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS;
    }
    else {
        sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT_COMPLETE;
    }
}

static void update_status_report_send_logs_state_handle(struct mender_statemachine *sm) {
    const char *logs;
    mender_err_t err;

    err = deployment_logger_get_logs(sm->update.id, &logs);
    if (err) {
        LOGE("Failed to get deployment logs for deployment [%s]: %08x",
            sm->update.id, err);
        /* there is nothing more we can do here */
        sm->current_state = MENDER_STATE_REPORT_STATUS_ERROR;
        return;
    }

    sm->updatestatusreport_state.tries_sending_logs++;

    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS_ASYNC;
    mender_upload_log(sm->mender, sm->update.id, logs, on_mender_result, sm);
}

static void update_status_report_send_logs_async_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err) {
        LOGE("failed to send deployment logs to server: %08x", err);
        if (MENDER_ERR_ISFATAL(err)) {
            /* there is no point in retrying */
            sm->current_state = MENDER_STATE_REPORT_STATUS_ERROR;
            return;
        }

        sm->updatestatusreportretry_state.tries_sending = sm->updatestatusreport_state.tries_sending_logs;
        sm->updatestatusreportretry_state.next_state = MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS;
        sm->current_state = MENDER_STATE_STATUS_REPORT_RETRY;
        return;
    }

    sm->current_state = MENDER_STATE_UPDATE_STATUS_REPORT_COMPLETE;
}

static void update_status_report_complete_state_handle(struct mender_statemachine *sm) {
    LOGD("reporting complete");
    /* stop deployment logging as the update is completed at this point */
    deployment_logger_disable();

    sm->current_state = MENDER_STATE_IDLE;
}

/*
 * try to send failed report at lest 3 times or keep trying every
 * 'retryPollInterval' for the duration of two 'updatePollInterval'
 */
static int max_sending_attempts(mender_duration_t upi, mender_duration_t rpi, int min_retries) {
    int max;

    if (rpi == 0) {
        return min_retries;
    }
    max = upi / rpi;
    if (max <= 3) {
        return min_retries;
    }
    return max * 2;
}

/* retry at least that many times */
static int min_report_send_retries = 3;

static void update_status_report_retry_state_handle(struct mender_statemachine *sm) {
    int max_try_sending;
    mender_duration_t retry = mender_get_retry_poll_interval(sm->mender);

    max_try_sending =
        max_sending_attempts(mender_get_update_poll_interval(sm->mender),
            retry, min_report_send_retries);
        /* we are always initializing with tries_sending = 1 */
    max_try_sending++;

    if (sm->updatestatusreportretry_state.tries_sending < max_try_sending) {
        sm->next_state_update = mender_time_now() + retry;
        sm->current_state = sm->updatestatusreportretry_state.next_state;
        return;
    }

    sm->current_state = MENDER_STATE_REPORT_STATUS_ERROR;
}

static void report_error_state_handle(struct mender_statemachine *sm) {
    /*
     * start deployment logging; no error checking
     * we can do nothing here; either we will have the logs or not...
     */
    deployment_logger_enable(sm->update.id);

    LOGE("handling report error state with status: %d", sm->deployment_status);

    switch (sm->deployment_status) {
    case MENDER_DEPLOYMENT_STATUS_SUCCESS:
        /* error while reporting success; rollback */
        sm->rollback_state.swap = true;
        sm->rollback_state.reboot = true;
        sm->current_state = MENDER_STATE_ROLLBACK;
        return;
    case MENDER_DEPLOYMENT_STATUS_FAILURE:
        /*
         * error while reporting failure;
         * start from scratch as previous update was broken
         */
        LOGE("error while performing update: %d", sm->deployment_status);
        sm->current_state = MENDER_STATE_IDLE;
        return;
    case MENDER_DEPLOYMENT_STATUS_ALREADY_INSTALLED:
        /*
         * we've failed to report already-installed status, not a big
         * deal, start from scratch
         */
        sm->current_state = MENDER_STATE_IDLE;
        return;
    default:
        /* should not end up here */
        sm->current_state = MENDER_STATE_DONE;
        return;
    }
}

static void reboot_state_handle(struct mender_statemachine *sm) {
    mender_err_t err;

    /* start deployment logging */
    err = deployment_logger_enable(sm->update.id);
    if (err) {
        /* just log error; we need to reboot anyway */
        LOGE("failed to enable deployment logger: %08x", err);
    }

    LOGD("handling reboot state");
    init_state_data(sm, MENDER_DEPLOYMENT_STATUS_INVALID);
    err = store_state_data(sm->store, &sm->sd);
    if (err) {
        /*
         * too late to do anything now, update is installed and enabled, let's play
         * along and reboot
         */
        LOGE("failed to store state data in reboot state: %08x, "
            "continuing with reboot", err);
    }

    sm->next_state_update = MENDER_TIME_INFINITE;
    sm->current_state = MENDER_STATE_REBOOT_ASYNC_REPORT;
    sm->deployment_status = MENDER_DEPLOYMENT_STATUS_REBOOTING;
    mender_report_update_status(sm->mender, sm->update.id,
        sm->deployment_status, on_mender_result, sm);
}

static void reboot_async_report_state_handle(struct mender_statemachine *sm) {
    mender_err_t err = sm->last_error;

    if (err && MENDER_ERR_ISFATAL(err)) {
        sm->rollback_state.swap = true;
        sm->rollback_state.reboot = false;
        sm->current_state = MENDER_STATE_ROLLBACK;
        return;
    }

    LOGI("rebooting device");

    err = mender_reboot(sm->mender);
    if (err) {
        LOGE("error rebooting device: %08x", err);
        sm->rollback_state.swap = true;
        sm->rollback_state.reboot = false;
        sm->current_state = MENDER_STATE_ROLLBACK;
        return;
    }

    /* we can not reach this point */
    sm->current_state = MENDER_STATE_DONE;
}

static void after_reboot_state_handle(struct mender_statemachine *sm) {
    /*
     * start deployment logging; no error checking
     * we can do nothing here; either we will have the logs or not...
     */
    deployment_logger_enable(sm->update.id);

    /* this state is needed to satisfy ToReboot transition Leave() action */
    LOGD("handling state after reboot");

    sm->current_state = MENDER_STATE_UPDATE_VERIFY;
}

static void rollback_state_handle(struct mender_statemachine *sm) {
    mender_err_t err;

    /* start deployment logging */
    err = deployment_logger_enable(sm->update.id);
    if (err) {
        /* just log error; we need to reboot anyway */
        LOGE("failed to enable deployment logger: %08x", err);
    }

    LOGI("performing rollback");

    /* swap active and inactive partitions and perform reboot */
    if (sm->rollback_state.swap) {
        err = mender_swap_partitions(sm->mender);
        if (err) {
            LOGE("rollback failed: %08x", err);
            sm->last_error = MENDER_ERR_FATAL(err);
            sm->current_state = MENDER_STATE_ERROR;
            return;
        }
    }
    if (sm->rollback_state.reboot) {
        LOGD("will try to rollback reboot the device");
        sm->current_state = MENDER_STATE_ROLLBACK_REBOOT;
        return;
    }

    /* if no reboot is needed, just return the error and start over */
    sm->last_error = MERR_UPDATE_FAILED;
    sm->current_state = MENDER_STATE_UPDATE_ERROR;
}

static void rollback_reboot_state_handle(struct mender_statemachine *sm) {
    mender_err_t err;

    /* start deployment logging */
    err = deployment_logger_enable(sm->update.id);
    if (err) {
        /* just log error; we need to reboot anyway */
        LOGE("failed to enable deployment logger: %08x", err);
    }

    LOGI("rebooting device after rollback");
    init_state_data(sm, MENDER_DEPLOYMENT_STATUS_INVALID);
    err = store_state_data(sm->store, &sm->sd);
    if (err) {
        /* too late to do anything now, let's play along and reboot */
        LOGE("failed to store state data in reboot state: %08x, "
            "continuing with reboot", err);
    }

    err = mender_reboot(sm->mender);
    if (err) {
        LOGE("error rebooting device: %08x", err);
        sm->last_error = MENDER_ERR_FATAL(err);
        sm->current_state = MENDER_STATE_ERROR;
        return;
    }

    /* we can not reach this point */
    sm->current_state = MENDER_STATE_DONE;
}

static void after_rollback_reboot_state_handle(struct mender_statemachine *sm) {
    mender_err_t err;

    /* start deployment logging */
    err = deployment_logger_enable(sm->update.id);
    if (err) {
        /* just log error; we need to reboot anyway */
        LOGE("failed to enable deployment logger: %08x", err);
    }

    /*
     * this state is needed to satisfy ToRollbackReboot
     * transition Leave() action
     */
    LOGD("handling state after rollback reboot");

    sm->last_error = MERR_UPDATE_FAILED;
    sm->current_state = MENDER_STATE_UPDATE_ERROR;
}

static void final_state_handle(struct mender_statemachine *sm) {
    LOGE("reached final state");
    sm->should_stop = true;
}

void mender_statemachine_create(struct mender_statemachine *sm, struct mender_store *store, struct mender *mender) {
    memset(sm, 0, sizeof(*sm));

    sm->mender = mender;
    sm->store = store;

    sm->current_state = MENDER_STATE_INIT;
    sm->next_state_update = 0;
    sm->should_stop = 0;

    sm->last_update_check = 0;
    sm->last_inventory_update = 0;
    sm->fetch_install_attempts = 0;

    sm->deployment_status = MENDER_DEPLOYMENT_STATUS_INVALID;
    sm->last_error = MERR_NONE;
}

static void do_handle_current_state(struct mender_statemachine *sm) {
    switch(sm->current_state) {
    case MENDER_STATE_INIT:
        init_state_handle(sm);
        break;
    case MENDER_STATE_IDLE:
        idle_state_handle(sm);
        break;
    case MENDER_STATE_AUTHORIZE:
        authorize_state_handle(sm);
        break;
    case MENDER_STATE_AUTHORIZE_ASYNC:
        authorize_async_state_handle(sm);
        break;
    case MENDER_STATE_AUTHORIZE_WAIT:
        authorize_wait_state_handle(sm);
        break;
    case MENDER_STATE_INVENTORY_UPDATE:
        inventory_update_state_handle(sm);
        break;
    case MENDER_STATE_INVENTORY_UPDATE_ASYNC:
        inventory_update_async_state_handle(sm);
        break;
    case MENDER_STATE_CHECK_WAIT:
        check_wait_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_CHECK:
        update_check_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_CHECK_ASYNC:
        update_check_async_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_FETCH:
        update_fetch_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_FETCH_SEND_REPORT_ASYNC:
        update_fetch_send_report_async_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_FETCH_SEND_DOFETCH_ASYNC:
        update_fetch_send_dofetch_async_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_STORE:
        update_store_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_STORE_ASYNC_REPORT:
        update_store_async_report_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_INSTALL:
        update_install_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_INSTALL_ASYNC_REPORT:
        update_install_async_report_state_handle(sm);
        break;
    case MENDER_STATE_FETCH_STORE_RETRY_WAIT:
        fetch_store_retry_wait_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_VERIFY:
        update_verify_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_COMMIT:
        update_commit_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_STATUS_REPORT:
        update_status_report_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT:
        update_status_report_send_report_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_STATUS_REPORT_SEND_REPORT_ASYNC:
        update_status_report_send_report_async_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS:
        update_status_report_send_logs_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_STATUS_REPORT_SEND_LOGS_ASYNC:
        update_status_report_send_logs_async_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_STATUS_REPORT_COMPLETE:
        update_status_report_complete_state_handle(sm);
        break;
    case MENDER_STATE_STATUS_REPORT_RETRY:
        update_status_report_retry_state_handle(sm);
        break;
    case MENDER_STATE_REPORT_STATUS_ERROR:
        report_error_state_handle(sm);
        break;
    case MENDER_STATE_REBOOT:
        reboot_state_handle(sm);
        break;
    case MENDER_STATE_REBOOT_ASYNC_REPORT:
        reboot_async_report_state_handle(sm);
        break;
    case MENDER_STATE_AFTER_REBOOT:
        after_reboot_state_handle(sm);
        break;
    case MENDER_STATE_ROLLBACK:
        rollback_state_handle(sm);
        break;
    case MENDER_STATE_ROLLBACK_REBOOT:
        rollback_reboot_state_handle(sm);
        break;
    case MENDER_STATE_AFTER_ROLLBACK_REBOOT:
        after_rollback_reboot_state_handle(sm);
        break;
    case MENDER_STATE_ERROR:
        error_state_handle(sm);
        break;
    case MENDER_STATE_UPDATE_ERROR:
        update_error_state_handle(sm);
        break;
    case MENDER_STATE_DONE:
        final_state_handle(sm);
        break;
    default:
        LOGE("Invalid state: %d", sm->current_state);
        sm->should_stop = true;
        break;
    }
}

mender_err_t mender_statemachine_run_once(struct mender_statemachine *sm) {
    enum mender_state last_state;
#ifndef MENDER_ENABLE_TESTING
    size_t stacksz;
#endif

    if (sm->should_stop) {
        LOGE("statemachine already stopped, stop calling me.");
        return MERR_STATEMACHINE_STOPPED;
    }

    if (sm->next_state_update == MENDER_TIME_INFINITE)
        return MERR_NONE;
    if (sm->next_state_update > mender_time_now())
        return MERR_NONE;

    /* this is techincally a hack, and we shouldn't rely on implementation details */
#ifndef MENDER_ENABLE_TESTING
    stacksz = mender_stack_num_used(sm->mender->stack);
    if (stacksz) {
        LOGW("LEAK: previous state didn't free the stack. Leaked %zu bytes", stacksz);
        mender_hexdump(mender_stack_base(sm->mender->stack), stacksz);
        mender_stack_give_all(sm->mender->stack);
    }
#endif

    LOGI("enter state: %s(%u)", mender_state_to_str(sm->current_state), sm->current_state);
    sm->next_state_update = 0;
    last_state = sm->current_state;
    do_handle_current_state(sm);
    sm->last_state = last_state;

    if (sm->should_stop) {
        sm->next_state_update = MENDER_TIME_INFINITE;
        return MERR_STATEMACHINE_STOPPED;
    }

    return MERR_NONE;
}

#ifdef MENDER_ENABLE_TESTING
#include "../tests/state.c"
#endif
