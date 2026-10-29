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
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/Variant.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/TypeTraits.h"
)
set(variant_compile_flags
    "-DCMAKE_CXX_STANDARD:STRING=11"
    "-DCMAKE_CXX_STANDARD_REQUIRED:BOOL=ON"
    "-DCMAKE_CXX_EXTENSIONS:BOOL=OFF"
)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
try_compile(variant_compile_control
    "${CMAKE_CURRENT_BINARY_DIR}/variant-compile/control"
    "${variant_compile_case_source}"
    CMAKE_FLAGS ${variant_compile_flags}
    COMPILE_DEFINITIONS "-DVARIANT_COMPILE_CASE=0"
    OUTPUT_VARIABLE variant_compile_output
)
if(NOT variant_compile_control)
    message(FATAL_ERROR "Variant compile control failed:\n${variant_compile_output}")
endif()
message(STATUS "Variant C++11 compile control: passed")

function(expect_variant_compile_failure case_number case_name diagnostic)
    set(result_var "variant_compile_case_${case_number}")
    try_compile(${result_var}
        "${CMAKE_CURRENT_BINARY_DIR}/variant-compile/${case_number}"
        "${variant_compile_case_source}"
        CMAKE_FLAGS ${variant_compile_flags}
        COMPILE_DEFINITIONS "-DVARIANT_COMPILE_CASE=${case_number}"
        OUTPUT_VARIABLE compile_output
    )
    if(${result_var})
        message(FATAL_ERROR "Variant ${case_name} unexpectedly compiled")
    endif()
    string(FIND "${compile_output}" "${diagnostic}" diagnostic_position)
    if(diagnostic_position EQUAL -1)
        message(FATAL_ERROR "Variant ${case_name} failed for the wrong reason:\n${compile_output}")
    endif()
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

# Independently check wrapper copy operations and unsupported payloads against
# a valid C++11 translation unit before accepting diagnostic-checked failures.
set(wrapper_compile_case_source "${CMAKE_CURRENT_SOURCE_DIR}/WrapperCompileCase.cpp")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${wrapper_compile_case_source}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/Optional.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/lib/Result.h"
)
try_compile(wrapper_compile_control
    "${CMAKE_CURRENT_BINARY_DIR}/wrapper-compile/control"
    "${wrapper_compile_case_source}"
    CMAKE_FLAGS ${variant_compile_flags}
    COMPILE_DEFINITIONS "-DWRAPPER_COMPILE_CASE=0"
    OUTPUT_VARIABLE wrapper_compile_output
)
if(NOT wrapper_compile_control)
    message(FATAL_ERROR "Wrapper compile control failed:\n${wrapper_compile_output}")
endif()
message(STATUS "Optional/Result C++11 compile control: passed")

function(expect_wrapper_compile_failure case_number case_name diagnostic)
    set(result_var "wrapper_compile_case_${case_number}")
    try_compile(${result_var}
        "${CMAKE_CURRENT_BINARY_DIR}/wrapper-compile/${case_number}"
        "${wrapper_compile_case_source}"
        CMAKE_FLAGS ${variant_compile_flags}
        COMPILE_DEFINITIONS "-DWRAPPER_COMPILE_CASE=${case_number}"
        OUTPUT_VARIABLE compile_output
    )
    if(${result_var})
        message(FATAL_ERROR "Optional/Result ${case_name} unexpectedly compiled")
    endif()
    string(FIND "${compile_output}" "${diagnostic}" diagnostic_position)
    if(diagnostic_position EQUAL -1)
        message(FATAL_ERROR "Optional/Result ${case_name} failed for the wrong reason:\n${compile_output}")
    endif()
    message(STATUS "Optional/Result C++11 negative compile ${case_name}: rejected as expected")
endfunction()

expect_wrapper_compile_failure(1 "Optional move-only copy construction" "deleted")
expect_wrapper_compile_failure(2 "Optional move-only copy assignment" "deleted")
expect_wrapper_compile_failure(3 "Result move-only copy construction" "deleted")
expect_wrapper_compile_failure(4 "Result move-only copy assignment" "deleted")
expect_wrapper_compile_failure(5 "Optional const mutation" "cannot assign to return value")
expect_wrapper_compile_failure(6 "Result const mutation" "cannot assign to return value")
expect_wrapper_compile_failure(7 "Optional void" "Optional cannot hold void")
expect_wrapper_compile_failure(8 "Optional reference" "Optional cannot hold references")
expect_wrapper_compile_failure(9 "Result void" "Result cannot hold void")
expect_wrapper_compile_failure(10 "Result reference" "Result cannot hold references")
expect_wrapper_compile_failure(11 "Result Error value" "Result cannot hold Error as its value type")

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
    LinesRangeTest.cpp
    FilesystemCollectionTest.cpp
    PathTest.cpp
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
    parsers/NameserverSelectionTest.cpp
    parsers/ResolvConfTest.cpp
    RegexFallbackTest.cpp
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

# A separate process links a test-instrumented copy of the real resolver.
# The linker-wrapped allocator cannot affect the normal test executable.
add_executable(filesystem-collection-allocation-test
    FilesystemCollectionAllocationTest.cpp
    ../src/lib/filesystem/FilesystemCollection.cpp
)
target_compile_definitions(filesystem-collection-allocation-test PRIVATE KOMPLI_TEST_ROOT_COPY_ALLOCATION=1)
target_link_options(filesystem-collection-allocation-test PRIVATE "LINKER:--wrap=_Znwm")
target_link_libraries(filesystem-collection-allocation-test PRIVATE
    OpenSSL::Crypto
    GTest::gtest_main
    GTest::gmock
    complianceenginelib
    logging
    commonutils
    parsonlib
)
gtest_discover_tests(filesystem-collection-allocation-test XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR})

add_library(file_regex_match_fallback_compile OBJECT ../src/lib/procedures/FileRegexMatch.cpp)
target_compile_definitions(file_regex_match_fallback_compile PRIVATE USE_REGEX_FALLBACK=1)
target_include_directories(file_regex_match_fallback_compile PRIVATE $<TARGET_PROPERTY:complianceenginelib,INCLUDE_DIRECTORIES>)
target_link_libraries(file_regex_match_fallback_compile PRIVATE complianceenginelib)
add_dependencies(complianceenginetests file_regex_match_fallback_compile)

gtest_discover_tests(complianceenginetests
    XML_OUTPUT_DIR ${GTEST_OUTPUT_DIR}
    TEST_LIST complianceenginetests_TESTS
)
set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/CTestProperties.cmake)
