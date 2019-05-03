cmake_minimum_required(VERSION 2.8)

project(test_tool C)

add_executable(test_tool test_client.c)

target_link_libraries(test_tool
    mender
)

# sanitizer
if (ENABLE_SANITIZER MATCHES ON)
add_sanitizers(test_tool)
endif()
