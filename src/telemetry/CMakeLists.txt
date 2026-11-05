# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.21)
project(telemetry)
get_filename_component(KOMPLI_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

if(BUILD_EXTERNAL)
    enable_testing()
    if(NOT(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "5.5"))
        add_subdirectory(lib)
        add_subdirectory(bin)
    endif()
endif()
