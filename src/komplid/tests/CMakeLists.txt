# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

include(GoogleTest)
find_package(GTest CONFIG REQUIRED)

add_executable(komplid-tests
    ProtocolTest.cpp
)

target_link_libraries(komplid-tests
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    pthread
    komplid-lib
)

gtest_discover_tests(komplid-tests XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR})
