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

#include <mender/http.h>
#include <mender/platform/transport_tcp.h>
#include <mender/platform/transport_ssl.h>
#include <mender/platform/log.h>
#include <mender/platform/eventloop.h>
#include <mender/authmgr.h>
#include <mender/platform/store.h>
#include <mender/platform/keystore.h>
#include <mender/platform/identity_data.h>
#include <mender/platform/inventory_data.h>
#include <mender/platform/device.h>
#include <mender/mender.h>
#include <mender/state.h>
#include <mender/utils.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>

static struct option long_options[] =
{
    {"help", no_argument, NULL, 'h'},
    {"certPath", required_argument, NULL, 'c'},
    {"storePath", required_argument, NULL, 'p'},
    {"keystorePath", required_argument, NULL, 'k'},
    {"artifactName", required_argument, NULL, 'a'},
    {"deviceType", required_argument, NULL, 'd'},
    {"serverUrl", required_argument, NULL, 's'},
    {"updateInterval", required_argument, NULL, 'u'},
    {"inventoryInterval", required_argument, NULL, 'i'},
    {"retryInterval", required_argument, NULL, 'r'},
    {"macAddress", required_argument, NULL, 'm'},
    {NULL, 0, NULL, 0}
};

static void print_usage(void) {
    printf("Usage:\n"
            "--help -h\t\t\t Display this information. \n"
            "--certPath -c <arg>\t\t Pass certificate path on as argument. \n"
            "--storePath -p <arg>\t\t Pass store path on as argument. \n"
            "--keystorePath -k <arg>\t\t Pass keystore path on as argument. \n"
            "--artifactName -a <arg>\t\t Pass artifact name on as argument. \n"
            "--deviceType -d <arg>\t\t Pass device type on as argument. \n"
            "--serverUrl -s <arg>\t\t Pass server url on as argument. \n"
            "--updateInterval -u <arg>\t Pass update interval on as argument. \n"
            "--inventoryInterval -i <arg>\t Pass inventory interval on as argument. \n"
            "--retryInterval -r <arg>\t Pass retry interval on as argument. \n"
            "--macAddress -m <arg>\t\t Pass MAC on as argument.\n\n");


    printf("Example_short:\n./test_tool -c ../certpath/cert.der -p ../data/menderstore -k ../data/keystore -a 1 -d TESTDEVICE -s localhost -u 10 -i 10 -r 10 -m 11:22:33:44:55:66\n\n");
    printf("Example_long:\n./test_tool --certPath ../certpath/cert.der --storePath ../data/menderstore --keystorePath ../data/keystore --artifactName 1 --deviceType TESTDEVICE --serverUrl localhost"
            "--updateInterval 10 --inventoryInterval 10 --retryInterval 10 --macAddress 11:22:33:44:55:66\n\n");
}

static void loop_cb(void *ctx) {
    struct mender_statemachine *sm = ctx;
    mender_err_t merr;

    merr = mender_statemachine_run_once(sm);
    if (merr) {
        LOGE("smerr: %u", merr);
        return;
    }
}

static void loop_get_timeout(void *ctx, mender_time_t *tnext) {
    struct mender_statemachine *sm = ctx;
    *tnext = sm->next_state_update;
}

static struct mender_platform_eventloop eventloop;
static struct mender_http_transport_tcp tcp;
static struct mender_http_transport_ssl ssl;
static struct mender_http_client client;
static struct mender_store store;
static struct mender_keystore keystore;
static struct mender_identity_data id_data;
static struct mender_inventory_data iv_data;
static struct mender_device dev;
static struct mender_authmgr authmgr;
static struct mender mender;
static struct mender_statemachine statemachine;
static uint8_t stack_buf[CONFIG_MENDER_MULTI_BUFFER_SZ];
static struct mender_stack stack;

int main(int argc, char **argv) {
    int rc, fd;
    struct stat sb;
    mender_err_t merr;
    struct eventloop_slot_loop loop;
    void *der;
    int option;
    char *cert_path = NULL;
    char *store_path = NULL;
    char *keystore_path = NULL;
    char *artifact_name = NULL;
    char *device_type = NULL;
    char *server_url = NULL;
    char *mac_address = NULL;
    int update_interval = 1800;
    int inventory_interval = 1800;
    int retry_interval = 300;



    while ((option = getopt_long(argc, argv, "hc:p:k:a:d:s:u:i:r:m:", long_options, NULL)) != -1)
    {
        // check to see if a single character or long option came through
        switch (option)
        {
            case 'h':
                print_usage();
                exit(1);
                break;

            case 'c':
                cert_path = optarg;
                break;

            case 'p':
                store_path = optarg;
                break;

            case 'k':
                keystore_path = optarg;
                break;

            case 'a':
                artifact_name = optarg;
                break;

            case 'd':
                device_type = optarg;
                break;

            case 's':
                server_url = optarg;
                break;

            case 'u':
                update_interval = atoi(optarg);
                break;

            case 'i':
                inventory_interval = atoi(optarg);
                break;

            case 'r':
                retry_interval = atoi(optarg);
                break;

            case 'm':
                mac_address = optarg;
                break;
        }
    }
    printf ("Arguments took: \nc = %s, p = %s, k = %s, a = %s, d = %s, s = %s, u = %d, i = %d, r = %d, m = %s\n",
            cert_path, store_path, keystore_path, artifact_name, device_type, server_url, update_interval, inventory_interval, retry_interval, mac_address);



    mender_stack_create(&stack, stack_buf, sizeof(stack_buf));


    fd = open(cert_path, O_RDONLY);

    if(fd < 0)
    {
        fprintf(stderr, "Error:\nCan not open %s : %s \n", cert_path, strerror(errno));
        return -1;
    }

    rc = fstat(fd, &sb);
    assert(rc == 0);

    der = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(der);

    mender_eventloop_create(&eventloop);

    mender_http_transport_tcp_create(&tcp, &eventloop);
    mender_http_transport_ssl_create(&ssl, &eventloop, der, sb.st_size);

    merr = mender_http_client_create(&client, &stack, &tcp.t, &ssl.t);
    assert(merr == 0);

    merr = mender_platform_store_create(&store, store_path);
    assert(merr == 0);

    merr = mender_platform_keystore_create(&keystore, keystore_path);
    assert(merr == 0);

    mender_platform_identity_data_create(&id_data, mac_address);
    mender_platform_inventory_data_create(&iv_data);

    mender_authmgr_create(&authmgr, &store, &keystore, &id_data);

    mender_platform_device_create(&dev, &store);

    mender_create(&mender, &store, &authmgr, &stack, &client, &dev, &iv_data,
        artifact_name, device_type, server_url, update_interval, inventory_interval, retry_interval);

    mender_statemachine_create(&statemachine, &store, &mender);

    memset(&loop, 0, sizeof(loop));
    loop.ctx = &statemachine;
    loop.cb = loop_cb;
    loop.get_timeout = loop_get_timeout;
    mender_eventloop_register_loop_cb(&eventloop, &loop);

    return mender_eventloop_run(&eventloop);
}
