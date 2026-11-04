# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_subdirectory(${CMAKE_SOURCE_DIR}/engine lib)
add_subdirectory(so)

if (BUILD_KOMPLI_CLI)
    add_subdirectory(${CMAKE_SOURCE_DIR}/benchmarkio benchmarkio)
    add_subdirectory(${CMAKE_SOURCE_DIR}/kompli kompli)
    if(BUILD_TESTS)
        add_subdirectory(${CMAKE_SOURCE_DIR}/tools/lua-evaluator lua-evaluator)
    endif(BUILD_TESTS)
endif(BUILD_KOMPLI_CLI)
