# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# The kompli daemon (komplid). See README.md for status: the JSONL wire
# protocol runs synchronous audit/remediate through the same Engine the
# `kompli` CLI uses, plus an opt-in SQLite-backed background-task/audit-cache
# registry (TaskRegistry) for rules listed in kompli.conf's
# backgroundTasks.rules. Gated by -DBUILD_KOMPLID (default ON) so it can be
# turned off for builds that don't want it.
project(komplid)
set(lib_name komplid-lib)

set(VCPKG_PACKAGES_DIR "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
find_package(unofficial-sqlite3 REQUIRED NO_DEFAULT_PATH PATHS ${VCPKG_PACKAGES_DIR})

# Library: wire protocol + peer auth + request dispatch + task/cache
# registry + background-task forking. Split out from the binary so unit
# tests can link the same object code as the shipping daemon without
# rebuilding it or duplicating sources (mirrors cli/CMakeLists.txt's
# kompli-cli-lib split).
add_library(${lib_name} STATIC
    BackgroundWorker.cpp
    Config.cpp
    PeerAuth.cpp
    Protocol.cpp
    RequestHandler.cpp
    TaskRegistry.cpp
)
target_include_directories(${lib_name} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(${lib_name} PUBLIC
    logging
    parsonlib
    complianceenginelib
    benchmarkio
    unofficial::sqlite3::sqlite3
)

add_executable(komplid Main.cpp)
target_link_libraries(komplid PRIVATE ${lib_name})

include(GNUInstallDirs)
install(TARGETS komplid RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Resolve the systemd system unit directory via pkg-config when available,
# falling back to the conventional path under CMAKE_INSTALL_PREFIX (=/usr,
# set at the top level) otherwise.
find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
    pkg_get_variable(SYSTEMD_UNIT_DIR systemd systemdsystemunitdir)
endif()
if (NOT SYSTEMD_UNIT_DIR)
    set(SYSTEMD_UNIT_DIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system")
endif()


install(FILES komplid.socket komplid@.service DESTINATION ${SYSTEMD_UNIT_DIR})

if (BUILD_TESTS)
    add_subdirectory(tests)
endif()

