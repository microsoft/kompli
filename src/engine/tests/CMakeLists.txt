# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_compile_options("-Wno-unused-const-variable")

project(kompli-engine-tests)

include(GoogleTest)
find_package(GTest CONFIG REQUIRED)

# Independently check each class's copy operations and unsupported payloads
# against its own valid C++11 translation unit before accepting failures.
set(wrapper_compile_flags
    "-DCMAKE_CXX_STANDARD:STRING=11"
    "-DCMAKE_CXX_STANDARD_REQUIRED:BOOL=ON"
    "-DCMAKE_CXX_EXTENSIONS:BOOL=OFF"
)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
# Result's cases live one per file under compile/, named for what each one
# checks, so a missing/renamed case is a path that doesn't exist rather than
# a silently-skipped preprocessor branch.
set(result_compile_case_dir "${CMAKE_CURRENT_SOURCE_DIR}/compile")
set(result_control_source "${result_compile_case_dir}/ResultControl.cpp")
set(result_rejects_copy_of_move_only_source "${result_compile_case_dir}/ResultRejectsCopyOfMoveOnly.cpp")
set(result_rejects_assignment_of_move_only_source "${result_compile_case_dir}/ResultRejectsAssignmentOfMoveOnly.cpp")
set(result_rejects_const_mutation_source "${result_compile_case_dir}/ResultRejectsConstMutation.cpp")
set(result_rejects_reference_source "${result_compile_case_dir}/ResultRejectsReference.cpp")
set(result_rejects_error_as_value_source "${result_compile_case_dir}/ResultRejectsErrorAsValue.cpp")
set(result_rejects_implicit_integer_error_source "${result_compile_case_dir}/ResultRejectsImplicitIntegerError.cpp")
set(result_rejects_throwing_move_source "${result_compile_case_dir}/ResultRejectsThrowingMove.cpp")
set(result_rejects_throwing_destructor_source "${result_compile_case_dir}/ResultRejectsThrowingDestructor.cpp")
set(result_rejects_const_rvalue_value_access_source "${result_compile_case_dir}/ResultRejectsConstRvalueValueAccess.cpp")
set(result_rejects_const_rvalue_error_access_source "${result_compile_case_dir}/ResultRejectsConstRvalueErrorAccess.cpp")
set(result_rejects_const_rvalue_arrow_access_source "${result_compile_case_dir}/ResultRejectsConstRvalueArrowAccess.cpp")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${result_control_source}"
    "${result_rejects_copy_of_move_only_source}"
    "${result_rejects_assignment_of_move_only_source}"
    "${result_rejects_const_mutation_source}"
    "${result_rejects_reference_source}"
    "${result_rejects_error_as_value_source}"
    "${result_rejects_implicit_integer_error_source}"
    "${result_rejects_throwing_move_source}"
    "${result_rejects_throwing_destructor_source}"
    "${result_rejects_const_rvalue_value_access_source}"
    "${result_rejects_const_rvalue_error_access_source}"
    "${result_rejects_const_rvalue_arrow_access_source}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../Result.h"
)

# The diagnostic argument accepts literal alternatives separated by |.
# Require a specific compiler diagnostic after the negative case fails.
function(require_compile_diagnostic subject case_name diagnostic)
    string(REPLACE "|" ";" diagnostic_alternatives "${diagnostic}")
    foreach(expected IN LISTS diagnostic_alternatives)
        string(FIND "${compile_output}" "${expected}" diagnostic_position)
        if(NOT diagnostic_position EQUAL -1)
            return()
        endif()
    endforeach()
    message(FATAL_ERROR "${subject} ${case_name} failed for the wrong reason:\n${compile_output}")
endfunction()

function(check_wrapper_compile_case subject source case_number case_name diagnostic)
    string(TOLOWER "${subject}" subject_lower)
    string(TOUPPER "${subject}" subject_upper)
    if(case_number EQUAL 0)
        set(result_var "${subject_lower}_compile_control")
        set(case_dir "control")
    else()
        set(result_var "${subject_lower}_compile_case_${case_number}")
        set(case_dir "${case_number}")
    endif()
    try_compile(${result_var}
        "${CMAKE_CURRENT_BINARY_DIR}/${subject_lower}-compile/${case_dir}"
        "${source}"
        CMAKE_FLAGS ${wrapper_compile_flags}
        COMPILE_DEFINITIONS "-D${subject_upper}_COMPILE_CASE=${case_number}"
        OUTPUT_VARIABLE compile_output
    )
    if(case_number EQUAL 0)
        if(NOT ${result_var})
            message(FATAL_ERROR "${subject} compile control failed:\n${compile_output}")
        endif()
        message(STATUS "${subject} C++11 compile control: passed")
        return()
    endif()
    if(${result_var})
        message(FATAL_ERROR "${subject} ${case_name} unexpectedly compiled")
    endif()
    require_compile_diagnostic("${subject}" "${case_name}" "${diagnostic}")
    message(STATUS "${subject} C++11 negative compile ${case_name}: rejected as expected")
endfunction()

check_wrapper_compile_case(Result "${result_control_source}" 0 "control" "")
check_wrapper_compile_case(Result "${result_rejects_copy_of_move_only_source}" 1 "move-only copy construction" "deleted")
check_wrapper_compile_case(Result "${result_rejects_assignment_of_move_only_source}" 2 "move-only copy assignment" "deleted")
check_wrapper_compile_case(Result "${result_rejects_const_mutation_source}" 3 "const mutation" "cannot assign to return value|assignment of read-only location")
check_wrapper_compile_case(Result "${result_rejects_reference_source}" 5 "reference" "Result cannot hold references")
check_wrapper_compile_case(Result "${result_rejects_error_as_value_source}" 6 "Error value" "Result cannot hold Error as its value type")
check_wrapper_compile_case(Result "${result_rejects_implicit_integer_error_source}" 9 "implicit integer Error" "no viable conversion|to non-scalar type")
check_wrapper_compile_case(Result "${result_rejects_throwing_move_source}" 10 "throwing move" "Result requires a nonthrowing move constructor")
check_wrapper_compile_case(Result "${result_rejects_throwing_destructor_source}" 11 "throwing destructor" "Result requires a nonthrowing destructor")
check_wrapper_compile_case(Result "${result_rejects_const_rvalue_value_access_source}" 12 "const rvalue Value access" "call to deleted member function|use of deleted function")
check_wrapper_compile_case(Result "${result_rejects_const_rvalue_error_access_source}" 13 "const rvalue Error access" "call to deleted member function|use of deleted function")
check_wrapper_compile_case(Result "${result_rejects_const_rvalue_arrow_access_source}" 14 "const rvalue arrow access" "call to deleted member function|use of deleted function")

set(PROCEDURES
    procedures/AideAttributesTest.cpp
    procedures/AksCommandTest.cpp
    procedures/AuditdRulesTest.cpp
    procedures/NoShellAccountsLockedTest.cpp
    procedures/ApparmorProfileStateTest.cpp
    procedures/DconfValueTest.cpp
    procedures/ShellTimeoutTest.cpp
    procedures/DefaultUmaskTest.cpp
    procedures/FileExistsTest.cpp
    procedures/FileSymlinkTargetTest.cpp
    procedures/FilePermissionsTest.cpp
    procedures/FilesystemMountOptionTest.cpp
    procedures/FirewalldZoneTargetsTest.cpp
    procedures/FirewallOpenPortsTest.cpp
    procedures/KernelModuleTest.cpp
    procedures/LogFilePermissionsTest.cpp
    procedures/LoginDefsOptionTest.cpp
    procedures/UniqueGroupIdTest.cpp
    procedures/GsettingsValueTest.cpp
    procedures/MountPointExistsTest.cpp
    procedures/NetworkInterfaceFlagTest.cpp
    procedures/MtaLocalOnlyTest.cpp
    procedures/NameserverCountTest.cpp
    procedures/NoDuplicateEntriesTest.cpp
    procedures/NoWorldWritableFilesTest.cpp
    procedures/PasswordChangeDateTest.cpp
    procedures/NoUnownedFilesTest.cpp
    procedures/RootPathSecurityTest.cpp
    procedures/SshKeyPermissionsTest.cpp
    procedures/SshdOptionTest.cpp
    procedures/SysctlValueTest.cpp
    procedures/SystemAccountShellTest.cpp
    procedures/UniqueUserIdTest.cpp
    procedures/WirelessDisabledTest.cpp
    procedures/XdmcpDisabledTest.cpp
    procedures/CommandOutputMatchTest.cpp
    procedures/FileRegexMatchTest.cpp
    procedures/PackageInstalledTest.cpp
    procedures/SystemdConfigTest.cpp
    procedures/SystemdUnitStateTest.cpp
    procedures/ufwStatusTest.cpp
    procedures/ShadowFieldTest.cpp
)

# Check that all globbed procedures are in the PROCEDURES list
file(GLOB GLOBBED_PROCEDURES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} procedures/*.cpp)
foreach(proc ${GLOBBED_PROCEDURES})
    if (NOT proc IN_LIST PROCEDURES)
        message(SEND_ERROR "Globbed procedure ${proc} is not in the PROCEDURES list.")
    endif()
endforeach()

add_executable(kompli-engine-tests
    CliContextTest.cpp
    Base64Test.cpp
    BenchmarkInfoTest.cpp
    BindingsTest.cpp
    CommonContextTest.cpp
    ComplianceEngineLoadUnloadTest.cpp
    ComplianceEngineTest.cpp
    DirToolsTest.cpp
    EngineTelemetryTest.cpp
    DistributionInfoTest.cpp
    EngineTest.cpp
    EvaluatorTest.cpp
    FileObjectCollectorTest.cpp
    FilesystemScannerTest.cpp
    JsonWrapperTest.cpp
    LuaEvaluatorTest.cpp
    LuaProceduresTest.cpp
    NetworkToolsTest.cpp
    NumericFileGroupTest.cpp
    OptionalTest.cpp
    RangesTest.cpp
    VariableResolverTest.cpp
    parsers/LoginDefsTest.cpp
    parsers/NameserverSelectionTest.cpp
    RegexTest.cpp
    ResultTest.cpp
    ResultEvidenceTest.cpp
    StringToolsTest.cpp
    TemporaryDirectoryTest.cpp
    UsersIteratorTest.cpp
    ${PROCEDURES}
)
# for ProcedureMap.h
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../src/lib)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../src/lib/procedures)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kompli-engine-tests
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    GTest::gmock_main
    pthread
    kompli-engine
    logging
    commonutils
    parsonlib
)

# Allocation-fault tests replace the global operator new, so they get their own
# executable; CTest runs it together with the other tests.
add_executable(result-allocation-test ResultAllocationTest.cpp)
target_link_libraries(result-allocation-test PRIVATE GTest::gtest_main)
gtest_discover_tests(result-allocation-test XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR})

gtest_discover_tests(kompli-engine-tests
    XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR}
    TEST_LIST kompli_engine_tests
)
set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/CTestProperties.cmake)
