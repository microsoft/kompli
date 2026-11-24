# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

add_compile_options("-Wno-unused-const-variable")

project(compliancetests)

include(GoogleTest)
find_package(GTest CONFIG REQUIRED)
set(VCPKG_PACKAGES_DIR "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
find_package(OpenSSL REQUIRED NO_DEFAULT_PATH PATHS ${VCPKG_PACKAGES_DIR})

# Compile a valid control first, then require each unsupported Variant use to
# fail for its specific constraint (not for a missing header or broken compiler).
set(variant_compile_case_source "${CMAKE_CURRENT_SOURCE_DIR}/VariantCompileCase.cpp")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${variant_compile_case_source}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../Variant.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../TypeTraits.h"
)
set(wrapper_compile_flags
    "-DCMAKE_CXX_STANDARD:STRING=11"
    "-DCMAKE_CXX_STANDARD_REQUIRED:BOOL=ON"
    "-DCMAKE_CXX_EXTENSIONS:BOOL=OFF"
)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
try_compile(variant_compile_control
    "${CMAKE_CURRENT_BINARY_DIR}/variant-compile/control"
    "${variant_compile_case_source}"
    CMAKE_FLAGS ${wrapper_compile_flags}
    COMPILE_DEFINITIONS "-DVARIANT_COMPILE_CASE=0"
    OUTPUT_VARIABLE variant_compile_output
)
if(NOT variant_compile_control)
    message(FATAL_ERROR "Variant compile control failed:\n${variant_compile_output}")
endif()
message(STATUS "Variant C++11 compile control: passed")

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

function(expect_variant_compile_failure case_number case_name diagnostic)
    set(result_var "variant_compile_case_${case_number}")
    try_compile(${result_var}
        "${CMAKE_CURRENT_BINARY_DIR}/variant-compile/${case_number}"
        "${variant_compile_case_source}"
        CMAKE_FLAGS ${wrapper_compile_flags}
        COMPILE_DEFINITIONS "-DVARIANT_COMPILE_CASE=${case_number}"
        OUTPUT_VARIABLE compile_output
    )
    if(${result_var})
        message(FATAL_ERROR "Variant ${case_name} unexpectedly compiled")
    endif()
    require_compile_diagnostic("Variant" "${case_name}" "${diagnostic}")
    message(STATUS "Variant C++11 negative compile ${case_name}: rejected as expected")
endfunction()

expect_variant_compile_failure(1 "empty list" "Variant requires at least one alternative")
expect_variant_compile_failure(2 "cv duplicate" "Variant alternatives must be distinct, ignoring cv")
expect_variant_compile_failure(3 "rvalue reference" "Variant cannot hold rvalue references")
expect_variant_compile_failure(4 "void" "Variant cannot hold void")
expect_variant_compile_failure(5 "throwing move" "Variant requires nonthrowing move constructors")
expect_variant_compile_failure(6 "deleted move assignment" "Variant requires nonthrowing move assignment")
# In C++11, is_nothrow_move_constructible is already false for a throwing
# destructor, even when its move constructor is explicitly noexcept.
expect_variant_compile_failure(7 "throwing destructor" "Variant requires nonthrowing move constructors")
expect_variant_compile_failure(8 "unlisted Is" "Variant query requires a listed alternative")
expect_variant_compile_failure(9 "cv-mismatched Is" "Variant query requires the exact listed cv-qualified type")
expect_variant_compile_failure(10 "unlisted As" "Variant query requires a listed alternative")
expect_variant_compile_failure(11 "cv-mismatched As" "Variant query requires the exact listed cv-qualified type")
expect_variant_compile_failure(12 "temporary reference binding" "Variant rejects temporary reference binding")
expect_variant_compile_failure(13 "const rvalue reference binding" "Variant rejects const rvalue reference binding")
expect_variant_compile_failure(14 "const to mutable reference binding" "Variant rejects const to mutable reference binding")
expect_variant_compile_failure(15 "numeric reference conversion" "Variant rejects numeric reference conversion")
expect_variant_compile_failure(16 "derived reference conversion" "Variant rejects derived reference conversion")
expect_variant_compile_failure(17 "unlisted reference Get" "Variant query requires a listed alternative")
expect_variant_compile_failure(18 "cv-mismatched reference Get" "Variant query requires the exact listed cv-qualified type")
expect_variant_compile_failure(19 "unlisted reference Is" "Variant query requires a listed alternative")
expect_variant_compile_failure(20 "unlisted reference As" "Variant query requires a listed alternative")
expect_variant_compile_failure(21 "cv-mismatched reference Is" "Variant query requires the exact listed cv-qualified type")
expect_variant_compile_failure(22 "cv-mismatched reference As" "Variant query requires the exact listed cv-qualified type")
expect_variant_compile_failure(23 "unlisted value Get" "Variant query requires a listed alternative")
expect_variant_compile_failure(24 "cv-mismatched value Get" "Variant query requires the exact listed cv-qualified type")
expect_variant_compile_failure(25 "non-exhaustive Visit" "Variant visitor must handle every alternative with the declared return type")
expect_variant_compile_failure(26 "inconsistent Visit result" "Variant visitor must handle every alternative with the declared return type")

# Independently check each class's copy operations and unsupported payloads
# against its own valid C++11 translation unit before accepting failures.
set(optional_compile_case_source "${CMAKE_CURRENT_SOURCE_DIR}/OptionalCompileCase.cpp")

# Result's cases live one per file under compile/, named for what each one
# checks, so a missing/renamed case is a path that doesn't exist rather than
# a silently-skipped preprocessor branch. The ResultVoid* names group
# Result<void>'s cases so they can travel together to a future PR.
set(result_compile_case_dir "${CMAKE_CURRENT_SOURCE_DIR}/compile")
set(result_control_source "${result_compile_case_dir}/ResultControl.cpp")
set(result_rejects_copy_of_move_only_source "${result_compile_case_dir}/ResultRejectsCopyOfMoveOnly.cpp")
set(result_rejects_assignment_of_move_only_source "${result_compile_case_dir}/ResultRejectsAssignmentOfMoveOnly.cpp")
set(result_rejects_const_mutation_source "${result_compile_case_dir}/ResultRejectsConstMutation.cpp")
set(result_void_rejects_value_access_source "${result_compile_case_dir}/ResultVoidRejectsValueAccess.cpp")
set(result_rejects_reference_source "${result_compile_case_dir}/ResultRejectsReference.cpp")
set(result_rejects_error_as_value_source "${result_compile_case_dir}/ResultRejectsErrorAsValue.cpp")
set(result_void_rejects_default_construction_source "${result_compile_case_dir}/ResultVoidRejectsDefaultConstruction.cpp")
set(result_void_rejects_empty_brace_return_source "${result_compile_case_dir}/ResultVoidRejectsEmptyBraceReturn.cpp")
set(result_rejects_implicit_integer_error_source "${result_compile_case_dir}/ResultRejectsImplicitIntegerError.cpp")
set(result_rejects_throwing_move_source "${result_compile_case_dir}/ResultRejectsThrowingMove.cpp")
set(result_rejects_throwing_destructor_source "${result_compile_case_dir}/ResultRejectsThrowingDestructor.cpp")
# Result<void> is not yet implemented by every PR this control travels to, so
# it gets its own control source and its own "must compile" check below
# rather than sharing ResultControl.cpp's Result<T> content.
set(result_void_control_source "${result_compile_case_dir}/ResultVoidControl.cpp")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${optional_compile_case_source}"
    "${result_control_source}"
    "${result_void_control_source}"
    "${result_rejects_copy_of_move_only_source}"
    "${result_rejects_assignment_of_move_only_source}"
    "${result_rejects_const_mutation_source}"
    "${result_void_rejects_value_access_source}"
    "${result_rejects_reference_source}"
    "${result_rejects_error_as_value_source}"
    "${result_void_rejects_default_construction_source}"
    "${result_void_rejects_empty_brace_return_source}"
    "${result_rejects_implicit_integer_error_source}"
    "${result_rejects_throwing_move_source}"
    "${result_rejects_throwing_destructor_source}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../Optional.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../Result.h"
)

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

# An additional, independent positive control for a part of a class not every
# PR has yet (e.g. Result<void>): same "must compile" check as case 0 above,
# under its own label so it doesn't collide with the class's main control.
function(check_wrapper_compile_control subject source label)
    string(TOLOWER "${subject}" subject_lower)
    string(TOLOWER "${label}" label_lower)
    try_compile("${subject_lower}_compile_control_${label_lower}"
        "${CMAKE_CURRENT_BINARY_DIR}/${subject_lower}-compile/control-${label_lower}"
        "${source}"
        CMAKE_FLAGS ${wrapper_compile_flags}
        OUTPUT_VARIABLE compile_output
    )
    if(NOT ${subject_lower}_compile_control_${label_lower})
        message(FATAL_ERROR "${subject} ${label} compile control failed:\n${compile_output}")
    endif()
    message(STATUS "${subject} C++11 ${label} compile control: passed")
endfunction()

check_wrapper_compile_case(Optional "${optional_compile_case_source}" 0 "control" "")
check_wrapper_compile_case(Optional "${optional_compile_case_source}" 1 "move-only copy construction" "deleted")
check_wrapper_compile_case(Optional "${optional_compile_case_source}" 2 "move-only copy assignment" "deleted")
check_wrapper_compile_case(Optional "${optional_compile_case_source}" 3 "const mutation" "cannot assign to return value|assignment of read-only location")
check_wrapper_compile_case(Optional "${optional_compile_case_source}" 4 "void" "Optional cannot hold void")
check_wrapper_compile_case(Optional "${optional_compile_case_source}" 5 "reference" "Optional cannot hold references")
check_wrapper_compile_case(Optional "${optional_compile_case_source}" 6 "throwing move" "Optional requires a nonthrowing move constructor")
check_wrapper_compile_case(Optional "${optional_compile_case_source}" 7 "throwing destructor" "Optional requires a nonthrowing destructor")

check_wrapper_compile_case(Result "${result_control_source}" 0 "control" "")
check_wrapper_compile_control(Result "${result_void_control_source}" "void")
check_wrapper_compile_case(Result "${result_rejects_copy_of_move_only_source}" 1 "move-only copy construction" "deleted")
check_wrapper_compile_case(Result "${result_rejects_assignment_of_move_only_source}" 2 "move-only copy assignment" "deleted")
check_wrapper_compile_case(Result "${result_rejects_const_mutation_source}" 3 "const mutation" "cannot assign to return value|assignment of read-only location")
check_wrapper_compile_case(Result "${result_void_rejects_value_access_source}" 4 "void Value access" "no member named 'Value'|no member named ‘Value’")
check_wrapper_compile_case(Result "${result_rejects_reference_source}" 5 "reference" "Result cannot hold references")
check_wrapper_compile_case(Result "${result_rejects_error_as_value_source}" 6 "Error value" "Result cannot hold Error as its value type")
check_wrapper_compile_case(Result "${result_void_rejects_default_construction_source}" 7 "void default construction" "calling a private constructor|is private within this context")
check_wrapper_compile_case(Result "${result_void_rejects_empty_brace_return_source}" 8 "void empty-brace return" "calling a private constructor|is private within this context")
check_wrapper_compile_case(Result "${result_rejects_implicit_integer_error_source}" 9 "implicit integer Error" "no viable conversion|to non-scalar type")
check_wrapper_compile_case(Result "${result_rejects_throwing_move_source}" 10 "throwing move" "Result requires a nonthrowing move constructor")
check_wrapper_compile_case(Result "${result_rejects_throwing_destructor_source}" 11 "throwing destructor" "Result requires a nonthrowing destructor")

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
    procedures/FileRegexMatchErrorsTest.cpp
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

add_executable(complianceenginetests
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
    DescriptorBoundaryTest.cpp
    DirectoryCursorBoundaryTest.cpp
    DescriptorAccessCompileTest.cpp
    PinAccessCompileTest.cpp
    PathAccessCompileTest.cpp
    FTWAccessCompileTest.cpp
    LinesRangeTest.cpp
    FilesystemCollectionTest.cpp
    PathTest.cpp
    PathTraversalTest.cpp
    PinTest.cpp
    ReadableFileTest.cpp
    FilesystemScannerTest.cpp
    JsonWrapperTest.cpp
    ListValidShellsTest.cpp
    LuaEvaluatorTest.cpp
    LuaProceduresTest.cpp
    NetworkToolsTest.cpp
    NumericFileGroupTest.cpp
    OptionalTest.cpp
    RangesTest.cpp
    VariableResolverTest.cpp
    parsers/LoginDefsTest.cpp
    parsers/ResolvConfTest.cpp
    RegexTest.cpp
    ResultTest.cpp
    ResultEvidenceTest.cpp
    StigTextPatternLoweringTest.cpp
    StigTextQuantifierSemanticsTest.cpp
    StringToolsTest.cpp
    TemporaryDirectoryTest.cpp
    UsersIteratorTest.cpp
    VariantTest.cpp
    ${PROCEDURES}
)
# for ProcedureMap.h
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../src/lib)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../src/lib/procedures)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(complianceenginetests
    OpenSSL::Crypto
    GTest::gtest
    GTest::gtest_main
    GTest::gmock
    GTest::gmock_main
    pthread
    complianceenginelib
    logging
    commonutils
    parsonlib
)

# Allocation-fault tests replace the global operator new, so they get their own
# executable; CTest runs it together with the other tests.
add_executable(result-allocation-test ResultAllocationTest.cpp)
target_link_libraries(result-allocation-test PRIVATE GTest::gtest_main)
gtest_discover_tests(result-allocation-test XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR})

# Allocation-fault tests replace the global operator new, so they get their own
# executable; CTest runs it together with the other tests.
add_executable(filesystem-scanner-allocation-test FilesystemScannerAllocationTest.cpp)
target_link_libraries(filesystem-scanner-allocation-test PRIVATE
    OpenSSL::Crypto
    GTest::gtest_main
    complianceenginelib
    logging
    commonutils
    parsonlib
)
gtest_discover_tests(filesystem-scanner-allocation-test XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR})

gtest_discover_tests(complianceenginetests
    XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR}
    TEST_LIST complianceenginetests_TESTS
)
set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/CTestProperties.cmake)
