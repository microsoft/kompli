# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_subdirectory(lib)
add_subdirectory(so)

if (BUILD_KOMPLI_CLI)
    add_subdirectory(benchmarkio)
    add_subdirectory(cli)
    if(BUILD_TESTS)
        add_subdirectory(lua-evaluator)
    endif(BUILD_TESTS)
endif(BUILD_KOMPLI_CLI)
