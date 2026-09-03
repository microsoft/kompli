# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(GoogleTest)
find_package(GTest CONFIG REQUIRED)

add_executable(kompli-cli-tests
    KompliResultSchemaTest.cpp
    BenchmarkFormatterTest.cpp
    CliOptionsTest.cpp
    JUnitRendererTest.cpp
    TextRenderersTest.cpp
)

target_include_directories(kompli-cli-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../tests
)

# The schema conformance test reads the shipped schema from the source tree.
target_compile_definitions(kompli-cli-tests PRIVATE
    KOMPLI_RESULT_SCHEMA_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../kompli-result.schema.json"
)

target_link_libraries(kompli-cli-tests
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    pthread
    kompli-cli-lib
)

gtest_discover_tests(kompli-cli-tests XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR})
