cmake_minimum_required(VERSION 2.8)
project(tests)

if (CODE_COVERAGE MATCHES ON)
# Include code coverage
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
include(CodeCoverage)

# add coverage target
SETUP_TARGET_FOR_COVERAGE(
    test_coverage
    ctest
    mender
)

# set cflags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_COVERAGE}" PARENT_SCOPE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_COVERAGE}")
endif()

# one big test executable, so we can run them on the target
add_executable(mender_test
    main.c
    alltests.c
)
# sanitizer
if (ENABLE_SANITIZER MATCHES ON)
add_sanitizers(mender_test)
endif()

target_link_libraries(mender_test cmocka mender)
add_test(mender_test mender_test)
