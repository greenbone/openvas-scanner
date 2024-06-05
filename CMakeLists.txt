# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required (VERSION 3.0)

message ("-- Configuring the Scanner...")

# VERSION: Always include major, minor and patch level.
project (openvas
  VERSION 23.4.0
  LANGUAGES C)

if (POLICY CMP0005)
  cmake_policy (SET CMP0005 NEW)
endif (POLICY CMP0005)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

OPTION (ENABLE_COVERAGE "Enable support for coverage analysis" OFF)

## Retrieve git revision (at configure time)
include (GetGit)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if (EXISTS "${CMAKE_SOURCE_DIR}/.git/")
    if (GIT_FOUND)
      Git_GET_REVISION(${CMAKE_SOURCE_DIR} ProjectRevision)
      set (GIT_REVISION "~git-${ProjectRevision}")
    endif (GIT_FOUND)
  endif (EXISTS "${CMAKE_SOURCE_DIR}/.git/")
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

## make format
message (STATUS "Looking for clang-format...")
find_program (CLANG_FORMAT clang-format)
if (CLANG_FORMAT)
  message (STATUS "Looking for clang-format... ${CLANG_FORMAT}")
  add_custom_target(format COMMAND ${CLANG_FORMAT} "-i" "./src/*.c" "./misc/*.c"
                    "./nasl/*.c" "./src/*.h" "./misc/*.h" "./nasl/*.h"
                    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
else (CLANG_FORMAT)
  message (STATUS "clang-format not found...")
endif (CLANG_FORMAT)

# Set dev version if this is a development version and not a full release,
# unset (put value 0 or delete line) before a full release and reset after.
set (PROJECT_DEV_VERSION 0)

# If PROJECT_DEV_VERSION is set, the version string will be set to:
#   "major.minor.patch~dev${PROJECT_DEV_VERSION}${GIT_REVISION}"
# If PROJECT_DEV_VERSION is NOT set, the version string will be set to:
#   "major.minor.patch${GIT_REVISION}"
# For CMAKE_BUILD_TYPE "Release" the git revision will be empty.
if (PROJECT_DEV_VERSION)
  set (PROJECT_VERSION_SUFFIX "~dev${PROJECT_DEV_VERSION}")
endif (PROJECT_DEV_VERSION)

set (PROJECT_VERSION_STRING "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}${PROJECT_VERSION_SUFFIX}${GIT_REVISION}")

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;openvas;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set (CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README.md")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")

set (CPACK_PACKAGE_VERSION "${PROJECT_VERSION_STRING}${PROJECT_VERSION_GIT}")

set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "The OpenVAS Project")
set (CPACK_SOURCE_IGNORE_FILES
"${CMAKE_BINARY_DIR}"
"/.git/"
"swp$"
"nasl/nasl_grammar.tab.c"
"nasl/nasl_grammar.tab.h"
"nasl/nasl_grammar.output"
)

include (CPack)

## Variables

if (SYSCONF_INSTALL_DIR)
  set (SYSCONFDIR "${SYSCONF_INSTALL_DIR}")
endif (SYSCONF_INSTALL_DIR)

if (NOT SYSCONFDIR)
  set (SYSCONFDIR "/etc")
endif (NOT SYSCONFDIR)

if (NOT EXEC_PREFIX)
  set (EXEC_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif (NOT EXEC_PREFIX)

if (NOT BINDIR)
  set (BINDIR "${EXEC_PREFIX}/bin")
endif (NOT BINDIR)

if (NOT SBINDIR)
  set (SBINDIR "${EXEC_PREFIX}/sbin")
endif (NOT SBINDIR)

if (NOT LIBDIR)
  set (_DEFAULT_LIBRARY_INSTALL_DIR lib)
  if (EXISTS "${EXEC_PREFIX}/lib32/" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    set (_DEFAULT_LIBRARY_INSTALL_DIR lib32)
  endif (EXISTS "${EXEC_PREFIX}/lib32/" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  if (EXISTS "${CMAKE_INSTALL_PREFIX}/lib64/" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    set (_DEFAULT_LIBRARY_INSTALL_DIR lib64)
  endif (EXISTS "${CMAKE_INSTALL_PREFIX}/lib64/" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  set( LIBRARY_INSTALL_DIR "${_DEFAULT_LIBRARY_INSTALL_DIR}")
  set (LIBDIR "${EXEC_PREFIX}/${LIBRARY_INSTALL_DIR}")
  message ("Set LIBDIR to ${LIBDIR}")
endif (NOT LIBDIR)

if (NOT LOCALSTATEDIR)
  set (LOCALSTATEDIR "/var")
endif (NOT LOCALSTATEDIR)

if (NOT DATADIR)
  set (DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif (NOT DATADIR)

if (NOT OPENVAS_RUN_DIR)
  set (OPENVAS_RUN_DIR "/run/ospd")
endif (NOT OPENVAS_RUN_DIR)

if (NOT DEFINED BUILD_WITH_NETSNMP)
  set (BUILD_WITH_NETSNMP TRUE)
endif (NOT DEFINED BUILD_WITH_NETSNMP)

set (OPENVAS_DATA_DIR    "${DATADIR}/openvas")
set (OPENVAS_STATE_DIR   "${LOCALSTATEDIR}/lib/openvas")

if (NOT OPENVAS_FEED_LOCK_PATH)
  set (OPENVAS_FEED_LOCK_PATH "${OPENVAS_STATE_DIR}/feed-update.lock")
endif (NOT OPENVAS_FEED_LOCK_PATH)
add_definitions (-DOPENVAS_FEED_LOCK_PATH="${OPENVAS_FEED_LOCK_PATH}")

if (NOT GVM_LOG_DIR)
	set (GVM_LOG_DIR         "${LOCALSTATEDIR}/log/gvm")
endif (NOT GVM_LOG_DIR)
set (OPENVAS_SYSCONF_DIR "${SYSCONFDIR}/openvas")
set (GVM_SYSCONF_DIR     "${SYSCONFDIR}/gvm")

if (NOT OPENVAS_NVT_DIR)
  set (OPENVAS_NVT_DIR     "${OPENVAS_STATE_DIR}/plugins")
endif (NOT OPENVAS_NVT_DIR)

if (NOT GVM_ACCESS_KEY_DIR)
	set (GVM_ACCESS_KEY_DIR "${GVM_SYSCONF_DIR}")
endif (NOT GVM_ACCESS_KEY_DIR)

if (NOT OPENVAS_GPG_BASE_DIR)
	set (OPENVAS_GPG_BASE_DIR "${OPENVAS_SYSCONF_DIR}")
endif (NOT OPENVAS_GPG_BASE_DIR)

set (OPENVAS_LIB_INSTALL_DIR     "${LIBDIR}")

set (OPENVAS_CONF     "${OPENVAS_SYSCONF_DIR}/openvas.conf")

set (NVT_TIMEOUT "320")
set (SCANNER_NVT_TIMEOUT "36000")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Version

set (OPENVAS_VERSION "${PROJECT_VERSION_STRING}")

# Configure Doxyfile with version number
configure_file (doc/man/openvas.8.in doc/man/openvas.8 @ONLY)
configure_file (VERSION.in VERSION @ONLY)
configure_file (src/openvas_log_conf.cmake_in src/openvas_log.conf)


## Testing

enable_testing ()

add_custom_target (tests
                   DEPENDS attack-test pcap-test ipc-openvas-test lsc-test)

## Program

if (ENABLE_COVERAGE)
  set (COVERAGE_FLAGS "--coverage")
endif (ENABLE_COVERAGE)

set (HARDENING_FLAGS            "-Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector")
set (LINKER_HARDENING_FLAGS     "-Wl,-z,relro -Wl,-z,now")
# The "-D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1" is necessary for GPGME!
set (GPGME_C_FLAGS              "-D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1")

set (CMAKE_C_FLAGS_RELEASE      "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS}")
set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} ${COVERAGE_FLAGS}")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${GPGME_C_FLAGS} \
                                -std=c11 \
                                -Wall \
                                -Wextra \
                                -Werror \
                                -Wpedantic \
                                -Wmissing-prototypes \
                                -Wshadow \
                                -Wsequence-point \
                                -D_BSD_SOURCE \
                                -D_ISOC11_SOURCE \
                                -D_SVID_SOURCE \
                                -D_DEFAULT_SOURCE")

if (NOT SKIP_SRC)
  add_subdirectory (misc)
  add_subdirectory (nasl)
  add_subdirectory (src)
endif (NOT SKIP_SRC)

## Documentation

add_subdirectory (doc)


## Tests

enable_testing ()

## End
