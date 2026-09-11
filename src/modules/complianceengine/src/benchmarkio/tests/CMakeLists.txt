# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(GoogleTest)
find_package(GTest CONFIG REQUIRED)

add_executable(benchmarkio-tests
    BenchmarkDefinitionTest.cpp
    InputSecurityTest.cpp
)

target_include_directories(benchmarkio-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../tests
)

target_link_libraries(benchmarkio-tests
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    pthread
    benchmarkio
)

gtest_discover_tests(benchmarkio-tests XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR})
