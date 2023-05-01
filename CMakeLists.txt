cmake_minimum_required(VERSION 3.14)
project(judger)
set(CMAKE_CXX_STANDARD 17)
include(FetchContent)

Set(FETCHCONTENT_QUIET FALSE)

FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/ArthurSonzogni/nlohmann_json_cmake_fetchcontent
    GIT_PROGRESS TRUE GIT_SHALLOW TRUE GIT_TAG v3.11.2
    USES_TERMINAL_DOWNLOAD TRUE)
FetchContent_MakeAvailable(json)

FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt
    GIT_PROGRESS TRUE GIT_SHALLOW TRUE GIT_TAG 9.1.0
    USES_TERMINAL_DOWNLOAD TRUE)
FetchContent_MakeAvailable(fmt)

FetchContent_Declare(libcurl
    GIT_REPOSITORY https://github.com/curl/curl
    GIT_PROGRESS TRUE GIT_SHALLOW TRUE GIT_TAG curl-8_0_1
    USES_TERMINAL_DOWNLOAD TRUE)
FetchContent_MakeAvailable(libcurl)

set(REPROC++ ON)
FetchContent_Declare(reproc
    GIT_REPOSITORY https://github.com/DaanDeMeyer/reproc
    GIT_PROGRESS TRUE GIT_SHALLOW TRUE GIT_TAG v14.2.4
    USES_TERMINAL_DOWNLOAD TRUE)
FetchContent_MakeAvailable(reproc)

add_executable(judger judger.cpp)
target_link_libraries(judger fmt::fmt nlohmann_json::nlohmann_json)

add_executable(builder builder.cpp)
target_link_libraries(builder reproc++ nlohmann_json::nlohmann_json)