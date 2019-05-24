[![Build Status](https://travis-ci.org/grandcentrix/cmender.svg?branch=master)](https://travis-ci.org/grandcentrix/cmender)
## CMENDER
Based on the Mender OTA client. Written in C and optimized for low memory usage so it can be used on low power devices like MCUs

## Dependencies
* cmake v2.8 or higher
* http_parser (Ubuntu: libhttp-parser-dev)
* mbedtls (Ubuntu: libmbedtls-dev)
* jsmn https://github.com/zserge/jsmn
Testing:  
* cmocka v1.1.2 or higher
Sanitizers:  
* sanitizers-cmake https://github.com/arsenm/sanitizers-cmake

## Features
* no dynamic memory allocation
* everything is based on non-blocking eventloop callbacks
* platform abstractions with sample implementations for posix (select-eventloop, sockets, mbedtls)
* supports both tcp and ssl, including server-certificate verification
* the statemachine is a port from the Go-version with state-scripts being the only missing feature

## Installation example
* Clone repo and make sure that all dependencies are met
* Inside root-dir of the repo
```
mkdir build && cd build
```
* cmake
```
CFLAGS="-I<repo-dir>/jsmn" LDFLAGS="-L<repo-dir>/jsmn" cmake -DCMAKE_BUILD_TYPE=Debug ..
```
* make
```
make
```

## Use with Sanitizer
Please see https://github.com/arsenm/sanitizers-cmake on what sanitizers can be enabled
* Example for Sanitizer memory:
```
CFLAGS="-I<repo-dir>/jsmn" LDFLAGS="-L<repo-dir>/jsmn" cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTING=ON -DENABLE_SANITIZER=ON -DSANITIZER_DIR="<repo-dir>/sanitizers-cmake" -DSANITIZE_MEMORY=On ..
```
* make
```
make
```
* run tests
```
./tests/mender_test
```
* Keep in mind that SANITIZE_MEMORY state is cached and if you want to enable another sanitizer you first have to turn SANITIZE_MEMORY off


## Test tool
### Dependencies
* Build successful
* Create folder structure
```
mkdir -p <data-dir>/menderstore
```

### Create required cert
```
openssl s_client -showcerts -connect <server-url>:443 </dev/null
```
* Copy the last Root CA into a file named cert.crt
* Convert .crt into .der
* Some servers  don't send the CA cert. In that case you have to obtain it using a different way.
```
openssl x509 -outform der -in cert.crt -out <data-dir>/cert.der
```

### Using the test tool
After building the project successfully and setting up the folder structure start the test client with the following command and display the help
```
./platform/linux/test_tool/test_tool -h
```

* After a deployment the test tool exits instead of a reboot a real device would do. Start the test tool again but set the artifact name to the deployed version. After that the server should display a successful deployment.

### Possible failures
* Deployment failed because artifact name does not match
This might happen if the artifact name does not match the deployed artifact name. After this you have to delete the file upgrade_available located in data/menderstore/ or set it's contents to 0x00 using a hex-editor
* Device does not show up to server
If you try to authorize a new device make sure to change the MAC-address. Your device wont show up if you already have a device authorized with the same MAC-address

## Credits
* https://github.com/mendersoftware/mender
* https://github.com/zserge/jsmn
* https://github.com/arsenm/sanitizers-cmake


## License
CMender is licensed under the Apache License, Version 2.0. See LICENSE for the full license text.

Apache v2.0 © grandcentrix GmbH
