# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# The kompli daemon (komplid). Currently a placeholder implementation - see
# README.md. Gated by -DBUILD_KOMPLID=ON (default OFF) so it does not affect
# default builds until real scaffolding lands.
project(komplid)

add_executable(komplid Main.cpp)
target_link_libraries(komplid PRIVATE parsonlib)

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
