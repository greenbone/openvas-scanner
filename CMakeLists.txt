# OpenVAS
# $Id$
# Description: Top-level cmake control for the Scanner.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2011-2015 Greenbone Networks GmbH
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

cmake_minimum_required (VERSION 2.6)

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
  if (EXISTS "${CMAKE_SOURCE_DIR}/.svn/")
    if (SVN_EXECUTABLE)
      Subversion_GET_REVISION(. ProjectRevision)
      set (SVN_REVISION ".SVN.r${ProjectRevision}")
    else (SVN_EXECUTABLE)
      set (SVN_REVISION ".SVN")
    endif (SVN_EXECUTABLE)
  endif (EXISTS "${CMAKE_SOURCE_DIR}/.svn/")
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

# TODO: Check pkg-config (maybe with code like in gsa/CMakeLists.txt).

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
set (CPACK_PACKAGE_VERSION_MAJOR "5")
set (CPACK_PACKAGE_VERSION_MINOR "0")

# Use this scheme for stable releases
set (CPACK_PACKAGE_VERSION_PATCH "7${SVN_REVISION}")
set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
# Use this scheme for +betaN and +rcN releases:
#set (CPACK_PACKAGE_VERSION_PATCH "+beta1${SVN_REVISION}")
#set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}${CPACK_PACKAGE_VERSION_PATCH}")

set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "The OpenVAS Project")
set (CPACK_SOURCE_IGNORE_FILES
"/.svn/"
"/_CPack_Packages/"
"/CMakeFiles/"
"cmake$"
"swp$"
"Cache.txt$"
".tar.gz"
"install_manifest.txt"
"Makefile"
"/doc/generated/"
"log.conf$"
"Doxyfile$"
"Doxyfile_full$"
"openvassd.8$"
"VERSION$"
"tools/openvas-mkcert$"
"tools/openvas-mkcert-client$"
"tools/openvas-nvt-sync$"
"tools/greenbone-nvt-sync$"
"doc/example_redis_2_4.conf$"
"doc/example_redis_2_6.conf$"
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
  set (LIBDIR "${EXEC_PREFIX}/lib")
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

set (OPENVAS_DATA_DIR    "${DATADIR}/openvas")
set (OPENVAS_STATE_DIR   "${LOCALSTATEDIR}/lib/openvas")
set (OPENVAS_LOG_DIR     "${LOCALSTATEDIR}/log/openvas")
set (OPENVAS_CACHE_DIR   "${LOCALSTATEDIR}/cache/openvas")
set (OPENVAS_PID_DIR     "${LOCALSTATEDIR}/run")
set (OPENVAS_SYSCONF_DIR "${SYSCONFDIR}/openvas")

set (OPENVAS_NVT_DIR     "${OPENVAS_STATE_DIR}/plugins")

set (OPENVAS_LIB_INSTALL_DIR     "${LIBDIR}")
set (OPENVAS_SCANNER_CERTIFICATE "${OPENVAS_STATE_DIR}/CA/servercert.pem")
set (OPENVAS_SCANNER_KEY         "${OPENVAS_STATE_DIR}/private/CA/serverkey.pem")
set (OPENVAS_CLIENT_CERTIFICATE  "${OPENVAS_STATE_DIR}/CA/clientcert.pem")
set (OPENVAS_CLIENT_KEY          "${OPENVAS_STATE_DIR}/private/CA/clientkey.pem")
set (OPENVAS_CA_CERTIFICATE      "${OPENVAS_STATE_DIR}/CA/cacert.pem")

set (OPENVASSD_MESSAGES "${OPENVAS_LOG_DIR}/openvassd.messages")
set (OPENVASSD_DEBUGMSG "${OPENVAS_LOG_DIR}/openvassd.dump")
set (OPENVASSD_CONF     "${OPENVAS_SYSCONF_DIR}/openvassd.conf")

set (NVT_TIMEOUT "320")
set (SCANNER_NVT_TIMEOUT "36000")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Dependency checks

pkg_check_modules (LIBOPENVAS_NASL REQUIRED libopenvas_nasl>=8.0.2)
pkg_check_modules (LIBOPENVAS_BASE REQUIRED libopenvas_base>=8.0.2)
pkg_check_modules (LIBOPENVAS_MISC REQUIRED libopenvas_misc>=8.0.2)
pkg_check_modules (LIBOPENVAS_OMP REQUIRED libopenvas_omp>=8.0.2)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.16)

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

string (REPLACE "
" "" OPENVASSD_VERSION ${CPACK_PACKAGE_VERSION})

# Configure Doxyfile with version number
configure_file (doc/Doxyfile.in doc/Doxyfile @ONLY)
configure_file (doc/Doxyfile_full.in doc/Doxyfile_full @ONLY)
configure_file (doc/openvassd.8.in doc/openvassd.8 @ONLY)
configure_file (doc/example_redis_2_4.conf.in doc/example_redis_2_4.conf @ONLY)
configure_file (doc/example_redis_2_6.conf.in doc/example_redis_2_6.conf @ONLY)
configure_file (VERSION.in VERSION @ONLY)
configure_file (tools/openvas-mkcert.in tools/openvas-mkcert @ONLY)
configure_file (tools/openvas-mkcert-client.in tools/openvas-mkcert-client @ONLY)
configure_file (tools/openvas-nvt-sync.in tools/openvas-nvt-sync @ONLY)
configure_file (tools/greenbone-nvt-sync.in tools/greenbone-nvt-sync @ONLY)
# TODO: Once  Scanner has a proper logging mechanism like Manager.
#configure_file (src/openvassd_log_conf.cmake_in src/openvassd_log.conf)

## Program

set (HARDENING_FLAGS            "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -Wl,-z,relro -Wl,-z,now")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -D_BSD_SOURCE -D_ISOC99_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE")

add_subdirectory (src)

## Documentation

add_subdirectory (doc)

## Install


## Install

install (FILES ${CMAKE_BINARY_DIR}/src/openvassd
  DESTINATION ${SBINDIR}
  PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
  GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

# TODO: Once Scanner has a proper logging mechanism like Manager.
#install (FILES openvassd_log.conf
#         DESTINATION ${OPENVAS_SYSCONF_DIR})

install (FILES ${CMAKE_BINARY_DIR}/tools/openvas-mkcert
               ${CMAKE_BINARY_DIR}/tools/openvas-nvt-sync
               ${CMAKE_BINARY_DIR}/tools/greenbone-nvt-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/tools/openvas-mkcert-client
         DESTINATION ${BINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_SOURCE_DIR}/doc/openvas-mkcert-client.1
          DESTINATION ${DATADIR}/man/man1 )

install (FILES ${CMAKE_BINARY_DIR}/doc/openvassd.8
         DESTINATION ${DATADIR}/man/man8 )

install (FILES ${CMAKE_SOURCE_DIR}/doc/openvas-mkcert.8
               ${CMAKE_SOURCE_DIR}/doc/openvas-nvt-sync.8
               ${CMAKE_SOURCE_DIR}/doc/greenbone-nvt-sync.8
         DESTINATION ${DATADIR}/man/man8 )

install (FILES ${CMAKE_BINARY_DIR}/doc/example_redis_2_4.conf
               ${CMAKE_BINARY_DIR}/doc/example_redis_2_6.conf
         DESTINATION ${DATADIR}/doc/openvas-scanner/ )

install (DIRECTORY DESTINATION ${OPENVAS_NVT_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_CACHE_DIR})

## Tests

enable_testing ()

## End
