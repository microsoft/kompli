# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set(found_override_test FALSE)
set(found_file_permissions_test FALSE)
set(found_log_file_permissions_test FALSE)

foreach(test_name IN LISTS complianceenginetests_TESTS)
    if(test_name STREQUAL "ComplianceEngineTest.ValidatePayload_OverrideFile")
        set_tests_properties("${test_name}" PROPERTIES RUN_SERIAL TRUE)
        set(found_override_test TRUE)
    elseif(test_name MATCHES "^EnsureFilePermissionsTest\\.")
        set_tests_properties("${test_name}" PROPERTIES RESOURCE_LOCK kompli_system_accounts)
        set(found_file_permissions_test TRUE)
    elseif(test_name MATCHES "^EnsureLogfileAccessTest\\.")
        set_tests_properties("${test_name}" PROPERTIES RESOURCE_LOCK kompli_system_accounts)
        set(found_log_file_permissions_test TRUE)
    endif()
endforeach()

if(NOT found_override_test OR NOT found_file_permissions_test OR NOT found_log_file_permissions_test)
    message(FATAL_ERROR "Failed to apply required parallel-safety properties to privileged tests")
endif()
