# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_executable(login-defs-parser-fuzzer LoginDefsTarget.cpp)
target_link_libraries(login-defs-parser-fuzzer PRIVATE
    complianceenginelib
    commonutils
    $<$<BOOL:${BUILD_TELEMETRY}>:telemetry-interface>
)
