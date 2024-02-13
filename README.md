# C-Mender

Based on the Mender OTA client. Written in C and optimized for low memory usage
so it can be used on low power devices like MCUs.

## Dependencies

* cmake v2.8 or higher
* http_parser (Ubuntu: libhttp-parser-dev)
* mbedtls (Ubuntu: libmbedtls-dev)
* [jsmn](https://github.com/zserge/jsmn)
* Testing (optional):
  * cmocka v1.1.2 or higher
* Sanitizers (optional):
  * [sanitizers-cmake](https://github.com/arsenm/sanitizers-cmake)

## Features

* No dynamic memory allocation
* Everything is based on non-blocking eventloop callbacks
* Platform abstractions with sample implementations for POSIX
  (select-eventloop, sockets, mbedtls)
* Supports both TCP and SSL, including server-certificate verification
* The statemachine is a port from the Go-client at version 1.5.0 with
  state-scripts being the only missing feature

## Installation example

* Clone repo and make sure that all dependencies are met
* Create build directory inside root-dir of the repo:

```bash
mkdir build && cd build
```

* Configure:

```bash
CFLAGS="-I<repo-dir>/jsmn" LDFLAGS="-L<repo-dir>/jsmn" cmake -DCMAKE_BUILD_TYPE=Debug ..
```

* Compile:

```bash
make
```

## Enable sanitizers

Please see [sanitizers-cmake](https://github.com/arsenm/sanitizers-cmake) on
what sanitizers can be enabled.

* Configure with memory sanitizer:

```bash
CFLAGS="-I<repo-dir>/jsmn" LDFLAGS="-L<repo-dir>/jsmn" cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTING=ON -DENABLE_SANITIZER=ON -DSANITIZER_DIR="<repo-dir>/sanitizers-cmake" -DSANITIZE_MEMORY=On ..
```

* Compile:

```bash
make
```

* Run tests:

```bash
./tests/mender_test
```

* Keep in mind that `SANITIZE_MEMORY` state is cached and if you want to enable
  another sanitizer you first have to turn `SANITIZE_MEMORY` off.

## Test tool

### One-time setup

* Build the client, or build container image when running macOS (container image only tested on intel macs):

```bash
docker build -t cmender-test-tool .
```

* Create menderstore directory:

```bash
mkdir -p <data-dir>/menderstore
```

* Create a client certificate:

```bash
openssl s_client -showcerts -connect <server-url>:443 </dev/null
```

* Copy the last Root CA into a file named `cert.crt`
  * Some servers don't send the CA cert. In that case you have to obtain it
    using a different way.
* Convert the client certificate from PEM to DER format:

```bash
openssl x509 -outform der -in cert.crt -out <data-dir>/cert.der
```

### Use the test tool

After building the project successfully and setting up the folder structure
start the test client with the following command and display the help:

```bash
./platform/linux/test_tool/test_tool -h
```

Or via docker:

```bash
docker run -v ./data:/data cmender-test-tool -h
```

After a deployment the test tool exits instead of a reboot a real device
would do. Start the test tool again but set the artifact name to the deployed
version. After that the server should indicate a successful deployment.

### Possible failures

* Deployment failed because artifact name does not match.
  This might happen if the artifact name does not match the deployed artifact
  name. After this you have to delete the file `upgrade_available` located in
  `data/menderstore/` or set it's contents to 0x00 using a hex-editor.
* Device does not show up to server.
  If you try to authorize a new device make sure to change the MAC-address.
  Your device wont show up if you already have a device authorized with the
  same MAC-address.

## Credits

* [Official mender client](https://github.com/mendersoftware/mender)
* [https://github.com/zserge/jsmn](jsmn)
* [https://github.com/arsenm/sanitizers-cmake](sanitizers-cmake)

## License

CMender is licensed under the Apache License, Version 2.0. See LICENSE for the full license text.

Apache v2.0 © grandcentrix GmbH
