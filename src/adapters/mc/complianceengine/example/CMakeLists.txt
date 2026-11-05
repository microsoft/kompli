# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

project(kompli-mc-example)

#add_custom_command(
#        OUTPUT ComplianceExample.mof
#        COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/MOFGenerator.py ${CMAKE_CURRENT_SOURCE_DIR}/ComplianceExample.json > ComplianceExample.mof
#        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/MOFGenerator.py ${CMAKE_CURRENT_SOURCE_DIR}/ComplianceExample.json
#        VERBATIM)

add_custom_target(kompli-mc-example-stage
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/Staging
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/ComplianceEngineExample.metaconfig.json" ${PROJECT_BINARY_DIR}/Staging/
#    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PROJECT_BINARY_DIR}/ComplianceEngineExample.mof" ${PROJECT_BINARY_DIR}/Staging/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/ComplianceEngineExample.mof" ${PROJECT_BINARY_DIR}/Staging/
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:kompli-mc-adapter> ${PROJECT_BINARY_DIR}/Staging/Modules/DscNativeResources/OsConfigResource/libOsConfigResource.so
    DEPENDS kompli-mc-adapter ComplianceEngineExample.mof)

add_custom_target(kompli-mc-example-zip ALL
    BYPRODUCTS ${KompliRootBinaryDir}/ComplianceEngineExample.zip
    COMMAND ${CMAKE_COMMAND} -E tar "cfv" "${KompliRootBinaryDir}/ComplianceEngineExample.zip" --format=zip .
    DEPENDS kompli-mc-example-stage
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/Staging/)
