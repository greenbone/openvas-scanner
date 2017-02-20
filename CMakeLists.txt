# OpenVAS
# $Id$
# Description: Top-level cmake control for the Scanner.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2011-2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

message ("-- Configuring the Scanner...")

project (openvas-scanner C)

cmake_minimum_required (VERSION 2.8)

if (POLICY CMP0005)
  cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

## Retrieve svn revision (at configure time)
#  Not using Subversion_WC_INFO, as it would have to connect to the repo
find_program (SVN_EXECUTABLE svn DOC "subversion command line client")

macro (Subversion_GET_REVISION dir variable)
  execute_process (COMMAND ${SVN_EXECUTABLE} info ${CMAKE_SOURCE_DIR}/${dir}
    OUTPUT_VARIABLE ${variable}
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  string (REGEX REPLACE "^(.*\n)?Revision: ([^\n]+).*"
    "\\2" ${variable} "${${variable}}")
endmacro (Subversion_GET_REVISION)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if (EXISTS "${CMAKE_SOURCE_DIR}/.svn/" OR EXISTS "${CMAKE_SOURCE_DIR}/../.svn/")
    if (SVN_EXECUTABLE)
      Subversion_GET_REVISION(. ProjectRevision)
      set (SVN_REVISION "~svn${ProjectRevision}")
    else (SVN_EXECUTABLE)
      set (SVN_REVISION "~svn")
    endif (SVN_EXECUTABLE)
  endif (EXISTS "${CMAKE_SOURCE_DIR}/.svn/" OR EXISTS "${CMAKE_SOURCE_DIR}/../.svn/")
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

# TODO: Check pkg-config (maybe with code like in gsa/CMakeLists.txt).

## Project version
# The following three variables should be set through the project command once
# we require CMake >= 3.0
set (PROJECT_VERSION_MAJOR 5)
set (PROJECT_VERSION_MINOR 2)
set (PROJECT_VERSION_PATCH 0)

# Set beta version if this is a beta release series,
# unset if this is a stable release series.
set (PROJECT_BETA_RELEASE 1)

if (SVN_REVISION)
  set (PROJECT_VERSION_SVN "${SVN_REVISION}")
endif (SVN_REVISION)

# If PROJECT_BETA_RELEASE is set, the version string will be set to:
#   "major.minor+beta${PROJECT_BETA_RELEASE}"
# If PROJECT_BETA_RELEASE is NOT set, the version string will be set to:
#   "major.minor.patch"
if (PROJECT_BETA_RELEASE)
  set (PROJECT_VERSION_SUFFIX "+beta${PROJECT_BETA_RELEASE}")
else (PROJECT_BETA_RELEASE)
  set (PROJECT_VERSION_SUFFIX ".${PROJECT_VERSION_PATCH}")
endif (PROJECT_BETA_RELEASE)

set (PROJECT_VERSION_STRING "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}${PROJECT_VERSION_SUFFIX}")

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;openvas-scanner;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README")
set (CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")

set (CPACK_PACKAGE_VERSION "${PROJECT_VERSION_STRING}${PROJECT_VERSION_SVN}")

set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "The OpenVAS Project")
set (CPACK_SOURCE_IGNORE_FILES
"${CMAKE_BINARY_DIR}"
"/.svn/"
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
  set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
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
  set (LOCALSTATEDIR "${CMAKE_INSTALL_PREFIX}/var")
endif (NOT LOCALSTATEDIR)

if (NOT DATADIR)
  set (DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif (NOT DATADIR)

#if (NOT SYSCONFDIR)
#  set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
#endif (NOT SYSCONFDIR)
if (NOT OPENVAS_RUN_DIR)
  set (OPENVAS_RUN_DIR "${LOCALSTATEDIR}/run")
endif (NOT OPENVAS_RUN_DIR)

set (OPENVAS_DATA_DIR    "${DATADIR}/openvas")
set (OPENVAS_STATE_DIR   "${LOCALSTATEDIR}/lib/openvas")
set (OPENVAS_LOG_DIR     "${LOCALSTATEDIR}/log/openvas")
set (OPENVAS_CACHE_DIR   "${LOCALSTATEDIR}/cache/openvas")
set (OPENVAS_SYSCONF_DIR "${SYSCONFDIR}/openvas")

if (NOT OPENVAS_NVT_DIR)
  set (OPENVAS_NVT_DIR     "${OPENVAS_STATE_DIR}/plugins")
endif (NOT OPENVAS_NVT_DIR)

if (NOT OPENVAS_ACCESS_KEY_DIR)
  set (OPENVAS_ACCESS_KEY_DIR "${OPENVAS_SYSCONF_DIR}")
endif (NOT OPENVAS_ACCESS_KEY_DIR)

set (OPENVAS_LIB_INSTALL_DIR     "${LIBDIR}")

set (OPENVASSD_DEBUGMSG "${OPENVAS_LOG_DIR}/openvassd.dump")
set (OPENVASSD_CONF     "${OPENVAS_SYSCONF_DIR}/openvassd.conf")

set (NVT_TIMEOUT "320")
set (SCANNER_NVT_TIMEOUT "36000")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Dependency checks

pkg_check_modules (LIBGVM_BASE REQUIRED libgvm_base>=1.0.0)
pkg_check_modules (LIBGVM_UTIL REQUIRED libgvm_util>=1.0.0)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.32)

message (STATUS "Looking for libgcrypt...")
find_library (GCRYPT gcrypt)
if (NOT GCRYPT)
  message (SEND_ERROR "The libgcrypt library is required.")
else (NOT GCRYPT)
  message (STATUS "Looking for libgcrypt... ${GCRYPT}")
  execute_process (COMMAND libgcrypt-config --libs
    OUTPUT_VARIABLE GCRYPT_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND libgcrypt-config --cflags
    OUTPUT_VARIABLE GCRYPT_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif (NOT GCRYPT)

## Version

set (OPENVASSD_VERSION "${PROJECT_VERSION_STRING}")

# Configure Doxyfile with version number
configure_file (doc/Doxyfile.in doc/Doxyfile @ONLY)
configure_file (doc/Doxyfile_full.in doc/Doxyfile_full @ONLY)
configure_file (doc/openvassd.8.in doc/openvassd.8 @ONLY)
configure_file (doc/example_redis_2_4.conf.in doc/example_redis_2_4.conf @ONLY)
configure_file (doc/example_redis_2_6.conf.in doc/example_redis_2_6.conf @ONLY)
configure_file (VERSION.in VERSION @ONLY)
configure_file (tools/greenbone-nvt-sync.in tools/greenbone-nvt-sync @ONLY)
configure_file (src/openvassd_log_conf.cmake_in src/openvassd_log.conf)

## Program

set (HARDENING_FLAGS            "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector")
set (LINKER_HARDENING_FLAGS     "-Wl,-z,relro -Wl,-z,now")
set (GPGME_C_FLAGS              "-D_FILE_OFFSET_BITS=64 -DLARGEFILE_SOURCE=1")

set (CMAKE_C_FLAGS_RELEASE      "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS}")

set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${GPGME_C_FLAGS} -Wall -D_BSD_SOURCE -D_ISOC99_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE")

add_subdirectory (misc)
add_subdirectory (nasl)
add_subdirectory (src)

## Documentation

add_subdirectory (doc)


## Tests

enable_testing ()

## End
