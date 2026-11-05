# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Compliance module for Linux
project(kompli-mc-adapter)
if (BUILD_FUZZER)
    add_link_options("LINKER:-z,defs" "-shared-libasan")
else (BUILD_FUZZER)
    add_link_options("LINKER:-z,defs")
endif (BUILD_FUZZER)
add_library(kompli-mc-adapter
    SHARED
        ../module.c
        ../schema.c
        ../OsConfigResource.c
        Baseline.c)

target_link_libraries(kompli-mc-adapter
    PRIVATE
        commonutils
        logging
        mpiclient
        parsonlib
        kompli-engine)

if(BUILD_TELEMETRY)
    list(APPEND STAGING_COMMANDS
        COMMAND ${CMAKE_COMMAND} -E rm -f ${PROJECT_BINARY_DIR}/StagingComplianceEngineShell/Modules/DscNativeResources/OsConfigResource/OSConfigTelemetry
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${BINARY_DIR}/bin/telemetrybin" ${PROJECT_BINARY_DIR}/StagingComplianceEngineShell/Modules/DscNativeResources/OsConfigResource/kompliTelemetry)
endif()

add_custom_target(kompli-mc-shell-stage
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/StagingComplianceEngineShell
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/ComplianceEngineShell.metaconfig.json" ${PROJECT_BINARY_DIR}/StagingComplianceEngineShell/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/ComplianceEngineShell.mof" ${PROJECT_BINARY_DIR}/StagingComplianceEngineShell
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:kompli-mc-adapter> ${PROJECT_BINARY_DIR}/StagingComplianceEngineShell/Modules/DscNativeResources/OsConfigResource/libOsConfigResource.so
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_PROPERTY:kompli-engine-schema,BINARY_DIR>/$<TARGET_PROPERTY:kompli-engine-schema,OUTPUT> ${PROJECT_BINARY_DIR}/StagingComplianceEngineShell/
    ${STAGING_COMMANDS}
    DEPENDS kompli-mc-adapter ComplianceEngineShell.mof kompli-engine-schema $<$<BOOL:${BUILD_TELEMETRY}>:telemetry-external>)

add_custom_target(kompli-mc-shell-zip ALL
    BYPRODUCTS ${KompliRootBinaryDir}/ComplianceEngineShell.zip
    COMMAND ${CMAKE_COMMAND} -E tar "cfv" "${KompliRootBinaryDir}/ComplianceEngineShell.zip" --format=zip .
    DEPENDS kompli-mc-shell-stage
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/StagingComplianceEngineShell/)

add_subdirectory(example)
