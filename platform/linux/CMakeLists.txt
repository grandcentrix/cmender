cmake_minimum_required(VERSION 2.8)
project(mender_platform C)

# platform
add_library(mender_platform
    ../posix/eventloop.c
    ../posix/http_transport_common.c
    ../posix/http_transport_tcp.c
    ../posix/http_transport_ssl.c
    ../posix/time.c
    ../posix/sha256.c
    identity_data.c
    inventory_data.c
    store.c
    keystore.c
    device.c
)

# sanitizer
if (ENABLE_SANITIZER MATCHES ON)
add_sanitizers(mender_platform)
endif()

target_link_libraries(mender_platform
    mbedtls
    mbedcrypto
    mbedx509
)
target_include_directories(mender_platform INTERFACE
    ../posix/include
    include
)
target_include_directories(mender_platform PRIVATE
    ../posix/include
    include
)
