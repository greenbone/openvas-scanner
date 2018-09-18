# OpenVAS-libraries/nasl
# $Id$
# Description: Top-level cmake control for the nasl library.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
#
# Copyright:
# Copyright (C) 2009-2018 Greenbone Networks GmbH
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

## Config

## Project version
# The following three variables should be set through the project command once
# we require CMake >= 3.0
set (NASL_VERSION_MAJOR 9)
set (NASL_VERSION_MINOR 1)
set (NASL_VERSION_PATCH 0)

if (PROJECT_BETA_RELEASE)
  set (NASL_VERSION_SUFFIX "+beta${PROJECT_BETA_RELEASE}")
else (PROJECT_BETA_RELEASE)
  set (NASL_VERSION_SUFFIX ".${PROJECT_VERSION_PATCH}")
endif (PROJECT_BETA_RELEASE)

set (NASL_VERSION_STRING "${NASL_VERSION_MAJOR}.${NASL_VERSION_MINOR}${NASL_VERSION_SUFFIX}")
set (NASL_PACKAGE_VERSION "${NASL_VERSION_STRING}${PROJECT_VERSION_GIT}")
set (NASL_VERSION "${NASL_VERSION_STRING}")

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (GIO REQUIRED gio-2.0)
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.2.15)
pkg_check_modules (LIBGVM_BASE REQUIRED libgvm_base>=1.0.0)
pkg_check_modules (LIBGVM_UTIL REQUIRED libgvm_util>=1.0.0)

pkg_check_modules (OPENVAS_WMICLIENT libopenvas_wmiclient>=1.0.1)
pkg_check_modules (OPENVAS_WINCMD libopenvas_wincmd>=1.0.1)


# for 'nasl' binary
pkg_check_modules (LIBSSH REQUIRED libssh>=0.6.0)

set (KSBA_MIN_VERSION "1.0.7")
message (STATUS "Looking for ksba >= ${KSBA_MIN_VERSION}...")
find_library (KSBA ksba)
message (STATUS "Looking for ksba >= ${KSBA_MIN_VERSION}... ${KSBA}")
if (NOT KSBA)
  message (SEND_ERROR "The ksba library is required.")
else (NOT KSBA)
  execute_process (COMMAND ksba-config --version
    OUTPUT_VARIABLE KSBA_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message (STATUS "Found ksba ${KSBA_VERSION}...")
  if (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
    message (SEND_ERROR "The ksba library >= ${KSBA_MIN_VERSION} is required.")
  else (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
    execute_process (COMMAND ksba-config --libs
      OUTPUT_VARIABLE KSBA_LDFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process (COMMAND ksba-config --cflags
      OUTPUT_VARIABLE KSBA_CFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif (${KSBA_VERSION} VERSION_LESS ${KSBA_MIN_VERSION})
endif (NOT KSBA)

message (STATUS "Looking for pcap...")
find_library (PCAP pcap)

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

message (STATUS "Looking for netsnmp...")
find_library (SNMP netsnmp)
message (STATUS "Looking for netsnmp... ${SNMP}")
if (SNMP)
  execute_process (COMMAND net-snmp-config --libs
    OUTPUT_VARIABLE SNMP_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif (SNMP)

message (STATUS "Looking for libgcrypt...")
find_library (GCRYPT gcrypt)
message (STATUS "Looking for libgcrypt... ${GCRYPT}")
if (NOT GCRYPT)
  message (SEND_ERROR "The libgcrypt library is required.")
else (NOT GCRYPT)
  execute_process (COMMAND libgcrypt-config --libs
    OUTPUT_VARIABLE GCRYPT_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND libgcrypt-config --cflags
    OUTPUT_VARIABLE GCRYPT_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND libgcrypt-config --version
    OUTPUT_VARIABLE GCRYPT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message (STATUS "  found libgcrypt, version ${GCRYPT_VERSION}")
  if (GCRYPT_VERSION VERSION_LESS "1.6")
    message (SEND_ERROR "libgcrypt 1.6 or greater is required")
  endif (GCRYPT_VERSION VERSION_LESS "1.6")
endif (NOT GCRYPT)


## Library
if (SNMP)
  add_definitions (-DHAVE_NETSNMP)
endif (SNMP)


# The "-fno-strict-aliasing" silences warnings caused by macros defined in byteorder.h.
# Once the warnings have been addressed this flag should be removed.
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -Wextra -fno-strict-aliasing")
set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror")

## Compile the parser - note that there are (better) CMake macros to achieve
## that
message (STATUS "Looking for bison...")
# We require bison >= 2.5 to distinguish between 'bison' and 'bison++'. They share the
# same binary name, but bison++ is at a lower version and does not seem to be actively
# developed anymore. NASL builds with bison, but not bison++ so we need to distinguish
# them here.
find_package (BISON 2.5)
if (NOT BISON_FOUND)
  message (SEND_ERROR "bison executable not found!")
else (NOT BISON_FOUND)
  add_custom_command (
    COMMAND ${BISON_EXECUTABLE}
     ARGS -d -v -t -p nasl ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.y
     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
     DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.y
     OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.tab.c
     OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.tab.h
     OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/nasl_grammar.output)
endif (NOT BISON_FOUND)

set (FILES arc4.c capture_packet.c charcnv.c exec.c genrand.c hmacmd5.c
     iconv.c lint.c md4.c md5.c nasl.c nasl_builtin_find_service.c
     nasl_builtin_openvas_tcp_scanner.c nasl_builtin_synscan.c nasl_builtin_nmap.c
     nasl_cmd_exec.c nasl_crypto2.c nasl_snmp.c nasl_ssh.c nasl_cert.c
     nasl_crypto.c nasl_debug.c nasl_func.c nasl_grammar.tab.c nasl_host.c
     nasl_http.c nasl_init.c nasl_lex_ctxt.c nasl_misc_funcs.c nasl_scanner_glue.c
     nasl_packet_forgery.c nasl_packet_forgery_v6.c nasl_signature.c nasl_smb.c
     nasl_socket.c nasl_text_utils.c nasl_tree.c nasl_var.c nasl_wmi.c
     nasl_isotime.c ntlmssp.c strutils.c smb_crypt.c smb_crypt2.c
     smb_signing.c time.c)


if (NOT OPENVAS_WMICLIENT_FOUND)
  set (FILES smb_interface_stub.c wmi_interface_stub.c ${FILES})
endif (NOT OPENVAS_WMICLIENT_FOUND)

if (NOT OPENVAS_WINCMD_FOUND)
  set (FILES smb_interface_stub.c ${FILES})
endif (NOT OPENVAS_WINCMD_FOUND)

if (KSBA)
  add_definitions (-DHAVE_LIBKSBA)
endif (KSBA)

if (OPENVASSD_CONF)
  add_definitions (-DOPENVASSD_CONF="${OPENVASSD_CONF}")
endif (OPENVASSD_CONF)

set_source_files_properties (nasl_grammar.tab.c GENERATED)

## Pass-throughs
add_definitions (-DOPENVAS_STATE_DIR="${OPENVAS_STATE_DIR}")
add_definitions (-DOPENVASLIB_VERSION="${OPENVASLIB_VERSION}")
add_definitions (-DOPENVAS_SYSCONF_DIR="${OPENVAS_SYSCONF_DIR}")

include_directories (${GLIB_INCLUDE_DIRS}
                     ${GPGME_INCLUDE_DIRS}
                     ${LIBSSH_INCLUDE_DIRS}
                     ${LIBGVM_BASE_INCLUDE_DIRS}
                     ${LIBGVM_UTIL_INCLUDE_DIRS}
                     ${KSBA_INCLUDE_DIRS})


# Build shared 
add_library (openvas_nasl_shared SHARED ${FILES})
set_target_properties (openvas_nasl_shared PROPERTIES OUTPUT_NAME "openvas_nasl")
set_target_properties (openvas_nasl_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties (openvas_nasl_shared PROPERTIES SOVERSION "${NASL_VERSION_MAJOR}")
set_target_properties (openvas_nasl_shared PROPERTIES VERSION "${NASL_PACKAGE_VERSION}")
# line bellow is needed so it also works with no-undefined which is e.g. used by Mandriva
target_link_libraries (openvas_nasl_shared openvas_misc_shared ${GLIB_LDFLAGS}
                         ${GCRYPT_LDFLAGS} ${GPGME_LDFLAGS} m
                         ${LIBGVM_BASE_LDFLAGS}
                         ${LIBGVM_UTIL_LDFLAGS}
                         ${OPENVAS_WMICLIENT_LDFLAGS} ${OPENVAS_WINCMD_LDFLAGS}
                         ${GNUTLS_LDFLAGS} ${PCAP_LDFLAGS} ${LIBSSH_LDFLAGS}
                         ${KSBA_LDFLAGS} ${SNMP_LDFLAGS}
                         ${LINKER_HARDENING_FLAGS})

# Link the openvas-nasl executable
add_executable (openvas-nasl nasl.c)
target_link_libraries (openvas-nasl openvas_nasl_shared openvas_misc_shared ${GNUTLS_LDFLAGS} ${LIBSSH_LDFLAGS})

# Link the openvas-nasl-lint executable
add_executable (openvas-nasl-lint nasl-lint.c)
target_link_libraries (openvas-nasl-lint openvas_nasl_shared openvas_misc_shared ${GLIB_LDFLAGS} ${GIO_LDFLAGS})

## Install

install (TARGETS openvas_nasl_shared openvas-nasl openvas-nasl-lint
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR})

install (FILES ${CMAKE_SOURCE_DIR}/doc/openvas-nasl.1
         DESTINATION ${DATADIR}/man/man1 )

install (FILES ${CMAKE_SOURCE_DIR}/doc/openvas-nasl-lint.1
         DESTINATION ${DATADIR}/man/man1 )
## End
