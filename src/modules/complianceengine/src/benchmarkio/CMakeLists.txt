# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Benchmark-definition parsing (BenchmarkDefinition) and root-safe input-file
# handling (InputSecurity). Split out of the CLI so both `kompli` (CLI) and
# `komplid` (planned daemon) can resolve and validate benchmark-definition
# files without depending on CLI-only presentation code.
project(benchmarkio)

add_library(benchmarkio STATIC
    BenchmarkDefinition.cpp
    InputSecurity.cpp
)

target_include_directories(benchmarkio PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(benchmarkio PUBLIC
    logging
    parsonlib
    complianceenginelib
    )

if (BUILD_TESTS)
    add_subdirectory(tests)
endif()

if (BUILD_FUZZER)
    add_subdirectory(fuzzer)
endif()
