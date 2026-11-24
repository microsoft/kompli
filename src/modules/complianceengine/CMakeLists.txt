# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_subdirectory(src)
if (BUILD_TESTS)
    add_subdirectory(${CMAKE_SOURCE_DIR}/engine/tests tests)
endif()
