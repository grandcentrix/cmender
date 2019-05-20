cmake_minimum_required(VERSION 2.8)
project(mender C)
enable_testing()

# options
option(CODE_COVERAGE "Code Coverage" OFF)
option(ENABLE_TESTING "compile test code" OFF)
option(ENABLE_SANITIZER "enable sanitizer" OFF)

# sanitizer
if (ENABLE_SANITIZER MATCHES ON)
set(CMAKE_MODULE_PATH "${SANITIZER_DIR}/cmake" ${CMAKE_MODULE_PATH})

find_package(Sanitizers)
endif()

# Check for JSMN
include(CheckIncludeFile)
find_library(JSMN jsmn)
add_definitions(
    -DJSMN_STATIC
)
CHECK_INCLUDE_FILE("jsmn.h" HAVE_JSMN_H)
if (NOT HAVE_JSMN_H)
    message( FATAL_ERROR "'jsmn.h' was not found" )
endif()

# global cflags
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Og -g")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_COVERAGE}")
add_compile_options(
    -std=gnu99
    -Wall
    -Wextra
    -Wshadow
    -Wmissing-prototypes
    -Wstrict-prototypes
    -Wdeclaration-after-statement
    -Werror
)
add_definitions(
    -DMBEDTLS_DEPRECATED_WARNING
)

# global includes
include_directories(
    include
)

add_definitions(
    -DCONFIG_MENDER_MULTI_BUFFER_SZ=0x1000
    -DCONFIG_MENDER_HTTP_RECV_BUFFER_SZ=128
)

if (ENABLE_TESTING MATCHES ON)
add_definitions(
    -DMENDER_ENABLE_TESTING
)
add_subdirectory(tests)
endif()

# submodules
add_subdirectory(platform/linux)
add_subdirectory(platform/linux/test_tool)

# mender
add_library(mender
    src/state.c
    src/deployment_logger.c
    src/mender.c
    src/authmgr.c
    src/client/client.c
    src/client/client_auth.c
    src/client/client_inventory.c
    src/client/client_update.c
    src/client/client_update_fetch.c
    src/client/client_status.c
    src/client/client_log.c
    src/installer.c
    src/installer_handlers.c
    src/http.c
    src/utils.c
    src/stack.c
    src/hexdump.c

    $<$<BOOL:${ENABLE_TESTING}>:tests/mock_flags.c>
    $<$<BOOL:${ENABLE_TESTING}>:tests/installer_test_data.c>
)

# sanitizer
if (ENABLE_SANITIZER MATCHES ON)
add_sanitizers(mender)
endif()

target_link_libraries(mender
    mender_platform
    http_parser
    $<$<BOOL:${JSMN}>:jsmn>
    $<$<BOOL:${ENABLE_TESTING}>:cmocka>
)
