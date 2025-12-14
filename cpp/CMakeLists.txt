cmake_minimum_required(VERSION 3.22)

project(verified_db LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_library(verified_db INTERFACE)
target_include_directories(verified_db INTERFACE ${CMAKE_CURRENT_LIST_DIR})

add_executable(test tests/test.cpp)

target_link_libraries(
  test
  PRIVATE
  GTest::gtest_main
  verified_db
)

find_package(OpenSSL REQUIRED)

target_link_libraries(verified_db INTERFACE OpenSSL::SSL)
