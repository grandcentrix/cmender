cmake_minimum_required(VERSION 2.8)
project(mender_platform C)

option(PLATFORM_KEYSTORE_ED25519 "use ed25519 keys" OFF)

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
    keystore$<$<BOOL:${PLATFORM_KEYSTORE_ED25519}>:-ed25519>.c
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
    $<$<BOOL:${PLATFORM_KEYSTORE_ED25519}>:sodium>
)
target_include_directories(mender_platform INTERFACE
    ../posix/include
    include
)
target_include_directories(mender_platform PRIVATE
    ../posix/include
    include
)
target_compile_definitions(mender_platform PUBLIC
    $<$<BOOL:${PLATFORM_KEYSTORE_ED25519}>:CONFIG_MENDER_PLATFORM_KEYSTORE_ED25519>
)
