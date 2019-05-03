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

#ifndef MENDER_STATE_H
#define MENDER_STATE_H

#include <mender/time.h>
#include <mender/platform/types.h>
#include <mender/client.h>
#include <mender/client_update.h>
#include <mender/store.h>
#include <mender/mender.h>

/* struct mender_statedata is state information that can be used for restoring state from storage */
struct mender_statedata {
    /* version is providing information about the format of the data */
    uint32_t version;
    /* number representing the id of the last state to execute */
    enum mender_state state;
    /* update reponse data for the update that was in progress */
    char artifact_name[32];
    char id[37];
    /* update status */
    uint32_t deployment_status;
};

struct mender_statemachine {
    /* statemachine data */
    enum mender_state current_state;
    enum mender_state last_state;
    mender_time_t next_state_update;
    int should_stop;

    /* external interfaces and common data */
    struct mender *mender;
    struct mender_store *store;
    mender_time_t last_update_check;
    mender_time_t last_inventory_update;
    int fetch_install_attempts;

    /* state data */
    struct mender_update_response update;
    enum mender_deployment_status deployment_status;
    mender_err_t last_error;
    struct mender_statedata sd;

    struct {
        int tries_sending_report;
        int tries_sending_logs;
    } updatestatusreport_state;

    struct {
        int tries_sending;
        enum mender_state next_state;
    } updatestatusreportretry_state;

    struct {
        bool swap;
        bool reboot;
    } rollback_state;
};

void mender_statemachine_create(struct mender_statemachine *sm, struct mender_store *store, struct mender *mender);
mender_err_t mender_statemachine_run_once(struct mender_statemachine *sm);

#endif /* MENDER_STATE_H */
