# Copyright (C) 2010-2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

## Dependency checks
##

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.6.4)

pkg_check_modules (LIBGVM_BASE REQUIRED libgvm_base>=20.8)
pkg_check_modules (LIBGVM_UTIL REQUIRED libgvm_util>=20.8)

pkg_check_modules (OPENVAS_WMICLIENT libopenvas_wmiclient>=1.0.5)
pkg_check_modules (OPENVAS_WINCMD libopenvas_wincmd>=1.0.5)

message (STATUS "Looking for pcap...")
find_library (PCAP pcap)
message (STATUS "Looking for pcap... ${PCAP}")
if (NOT PCAP)
  message (SEND_ERROR "The pcap library is required.")
endif (NOT PCAP)

message (STATUS "Looking for pcap-config...")
find_program (PCAP_CONFIG pcap-config)

if (PCAP_CONFIG)
  message (STATUS "Looking for pcap-config... ${PCAP_CONFIG}")
  execute_process (COMMAND pcap-config --libs
    OUTPUT_VARIABLE PCAP_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND pcap-config --cflags
    OUTPUT_VARIABLE PCAP_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
else (PCAP_CONFIG)
  message (STATUS "pcap-config not found, using defaults...")
  set (PCAP_LDFLAGS "-L/usr/lib -lpcap")
  set (PCAP_CFLAGS "-I/usr/include")
endif (PCAP_CONFIG)

message (STATUS "Looking for gpgme...")
find_library (GPGME gpgme)
message (STATUS "Looking for gpgme... ${GPGME}")
if (NOT GPGME)
  message (SEND_ERROR "The gpgme library is required.")
endif (NOT GPGME)

execute_process (COMMAND gpgme-config --libs
  OUTPUT_VARIABLE GPGME_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND gpgme-config --cflags
  OUTPUT_VARIABLE GPGME_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")


## Pass-throughs

include_directories (${GLIB_INCLUDE_DIRS}
                     ${LIBGVM_BASE_INCLUDE_DIRS}
                     ${GNUTLS_INCLUDE_DIRS})

# Library

set (FILES bpf_share.c ftp_funcs.c vendorversion.c network.c plugutils.c pcap.c
     strutils.c)


# On windows we are always PIC and stack-protector is replaces by DEP
# Also stack protection needs a shared library to work
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

## Project version
# The following three variables should be set through the project command once
# we require CMake >= 3.0
set (MISC_VERSION_MAJOR 20)
set (MISC_VERSION_MINOR 8)
set (MISC_VERSION_PATCH 0)

if (PROJECT_BETA_RELEASE)
  set (MISC_VERSION_SUFFIX "+beta${PROJECT_BETA_RELEASE}")
else (PROJECT_BETA_RELEASE)
  set (MISC_VERSION_SUFFIX ".${PROJECT_VERSION_PATCH}")
endif (PROJECT_BETA_RELEASE)

set (MISC_VERSION_STRING "${MISC_VERSION_MAJOR}.${MISC_VERSION_MINOR}${MISC_VERSION_SUFFIX}")
if (PROJECT_BETA_RELEASE)
  set (MISC_PACKAGE_VERSION "${MISC_VERSION_STRING}${PROJECT_VERSION_GIT}")
else (PROJECT_BETA_RELEASE)
  set (MISC_PACKAGE_VERSION "${MISC_VERSION_STRING}")
endif (PROJECT_BETA_RELEASE)
set (MISC_VERSION "${MISC_VERSION_STRING}")


# Build shared

add_library (openvas_misc_shared SHARED ${FILES})

set_target_properties (openvas_misc_shared PROPERTIES OUTPUT_NAME "openvas_misc")
set_target_properties (openvas_misc_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_misc_shared PROPERTIES SOVERSION "${MISC_VERSION_MAJOR}")
set_target_properties (openvas_misc_shared PROPERTIES VERSION "${MISC_PACKAGE_VERSION}")

target_link_libraries (openvas_misc_shared LINK_PRIVATE ${GNUTLS_LDFLAGS} ${UUID_LDFLAGS}
                       ${GLIB_LDFLAGS} ${PCAP_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS})

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR="${OPENVAS_STATE_DIR}")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR="${OPENVAS_DATA_DIR}")
endif (OPENVAS_DATA_DIR)

# @todo Why is this definition setting guarded? OPENVAS_SYSCONF_DIR should
#       always be set.
#$(COMPILE) -DOPENVAS_STATE_DIR=\"$(localstatedir)\" -DCONF_DIR=\"$(sysconfdir)\" -c services1.c
if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR="${OPENVAS_SYSCONF_DIR}")
endif (OPENVAS_SYSCONF_DIR)

# install library

install (TARGETS openvas_misc_shared
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR})

install (DIRECTORY DESTINATION ${GVM_LOG_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_DATA_DIR})
install (DIRECTORY DESTINATION ${OPENVAS_SYSCONF_DIR})
install (DIRECTORY
  DESTINATION ${OPENVAS_SYSCONF_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)
install (DIRECTORY
  DESTINATION ${OPENVAS_STATE_DIR}/gnupg
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE)

## Tests

enable_testing ()

set (ALIVEDETECTION_TEST_LINKER_WRAP_OPTIONS
     "-Wl,-wrap,socket,-wrap,setsockopt")
add_executable (pcap-test
                EXCLUDE_FROM_ALL
                pcap_tests.c)
add_test (pcap-test pcap-test)
target_include_directories (pcap-test PRIVATE ${CGREEN_INCLUDE_DIRS})
target_link_libraries (pcap-test cgreen
                       ${LIBGVM_BASE_LDFLAGS}
                       ${GLIB_LDFLAGS}
                       ${PCAP_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT}
                       ${ALIVEDETECTION_TEST_LINKER_WRAP_OPTIONS})
add_custom_target (tests-pcap
                  DEPENDS pcap-test)

## End
