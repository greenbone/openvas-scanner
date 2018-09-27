# OpenVAS
# $Id$
# Description: CMakefile for the OpenVAS Scanner program
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2011, 2018 Greenbone Networks GmbH
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

## Program

## Dependency checks

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

pkg_check_modules (LIBGVM_BASE REQUIRED libgvm_base>=1.0.0)
pkg_check_modules (LIBGVM_UTIL REQUIRED libgvm_util>=1.0.0)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)

# set NVTICACHE_STR with version.
if (LIBGVM_UTIL_VERSION)
  set (NVTICACHE_STR "nvticache${LIBGVM_UTIL_VERSION}")
  add_definitions (-DNVTICACHE_STR="${NVTICACHE_STR}")
endif (LIBGVM_UTIL_VERSION)

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
  execute_process (COMMAND libgcrypt-config --version
    OUTPUT_VARIABLE GCRYPT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message (STATUS "  found libgcrypt, version ${GCRYPT_VERSION}")
  if (GCRYPT_VERSION VERSION_LESS "1.6")
    message (SEND_ERROR "libgcrypt 1.6 or greater is required")
  endif (GCRYPT_VERSION VERSION_LESS "1.6")
endif (NOT GCRYPT)

add_executable (openvassd attack.c comm.c hosts.c
                nasl_plugins.c ntp.c openvassd.c otp.c
                pluginlaunch.c pluginload.c
                pluginscheduler.c plugs_req.c
                processes.c sighand.c utils.c)

set_target_properties (openvassd PROPERTIES LINKER_LANGUAGE C)

include_directories (${GLIB_INCLUDE_DIRS} ${LIBOPENVAS_NASL_INCLUDE_DIRS}
                     ${LIBGVM_BASE_INCLUDE_DIRS}
                     ${LIBOPENVAS_MISC_INCLUDE_DIRS})

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  # If we got GIT_REVISION at configure time,
  # assume we can get it at build time as well
  if (GIT_REVISION)
    # a custom target that is always built
    add_custom_target (revisiontag ALL)

    # creates gitversion.h using cmake script
    add_custom_command (TARGET revisiontag COMMAND ${CMAKE_COMMAND}
                        -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
                        -P ${CMAKE_SOURCE_DIR}/cmake/GetGit.cmake)

    # explicitly say that the executable depends on custom target
    add_dependencies (openvassd revisiontag)

    # include the output directory, where the gitversion.h file is generated
    include_directories (${CMAKE_CURRENT_BINARY_DIR})
    add_definitions (-DGIT_REV_AVAILABLE)
  endif (GIT_REVISION)
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror -Wextra")

if (OPENVASSD_VERSION)
  add_definitions (-DOPENVASSD_VERSION="${OPENVASSD_VERSION}")
endif (OPENVASSD_VERSION)

add_definitions (-DPREFIX="${CMAKE_INSTALL_PREFIX}")

if (OPENVAS_NVT_DIR)
  add_definitions (-DOPENVAS_NVT_DIR="${OPENVAS_NVT_DIR}")
endif (OPENVAS_NVT_DIR)

if (OPENVASSD_CONF)
  add_definitions (-DOPENVASSD_CONF="${OPENVASSD_CONF}")
endif (OPENVASSD_CONF)

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR="${OPENVAS_STATE_DIR}")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_RUN_DIR)
  add_definitions (-DOPENVAS_RUN_DIR="${OPENVAS_RUN_DIR}")
endif (OPENVAS_RUN_DIR)

if (SYSCONFDIR)
  add_definitions (-DSYSCONFDIR="${SYSCONFDIR}")
endif (SYSCONFDIR)

if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR="${OPENVAS_SYSCONF_DIR}")
endif (OPENVAS_SYSCONF_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR="${OPENVAS_DATA_DIR}")
endif (OPENVAS_DATA_DIR)

if (NVT_TIMEOUT)
  add_definitions (-DNVT_TIMEOUT=${NVT_TIMEOUT})
endif (NVT_TIMEOUT)

if (SCANNER_NVT_TIMEOUT)
  add_definitions (-DSCANNER_NVT_TIMEOUT=${SCANNER_NVT_TIMEOUT})
endif (SCANNER_NVT_TIMEOUT)

if (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  set (EXECINFO_LDFLAGS "execinfo")
endif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")


target_link_libraries (openvassd openvas_nasl_shared ${LIBOPENVAS_NASL_LDFLAGS}
                       ${LIBOPENVAS_MISC_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS}
                       ${GLIB_LDFLAGS} ${GCRYPT_LDFLAGS}
                       ${EXECINFO_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS})

## Tests

enable_testing ()

## Static analysis

add_custom_target (cppcheck COMMENT "Running cppcheck..."
                   COMMAND sh -c \"cppcheck ${CMAKE_CURRENT_SOURCE_DIR}\")

add_custom_target (check COMMENT "Checking code...")
add_dependencies (check cppcheck)

## Tag files

set (C_FILES "attack.c" "comm.c" "hosts.c"
     "nasl_plugins.c" "ntp.c" "openvassd.c" "otp.c"
     "pluginlaunch.c" "pluginload.c"
     "pluginscheduler.c" "plugs_req.c"
     "processes.c" "sighand.c" "utils.c")
add_custom_target (etags COMMENT "Building TAGS..."
                   COMMAND etags ${C_FILES})
add_custom_target (ctags COMMENT "Building tags..."
                   COMMAND ctags ${C_FILES})
add_custom_target (tags COMMENT "Building tags files...")
add_dependencies (tags etags ctags)

## Install

install (TARGETS openvassd
         RUNTIME DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
         GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/src/openvassd_log.conf
         DESTINATION ${OPENVAS_SYSCONF_DIR})

install (FILES ${CMAKE_BINARY_DIR}/tools/greenbone-nvt-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/doc/openvassd.8
         DESTINATION ${DATADIR}/man/man8 )


install (FILES ${CMAKE_SOURCE_DIR}/doc/greenbone-nvt-sync.8
         DESTINATION ${DATADIR}/man/man8 )

install (FILES ${CMAKE_BINARY_DIR}/doc/redis_config_examples/redis_2_4.conf
               ${CMAKE_BINARY_DIR}/doc/redis_config_examples/redis_2_6.conf
               ${CMAKE_BINARY_DIR}/doc/redis_config_examples/redis_2_8.conf
               ${CMAKE_BINARY_DIR}/doc/redis_config_examples/redis_3_0.conf
               ${CMAKE_BINARY_DIR}/doc/redis_config_examples/redis_3_2.conf
               ${CMAKE_BINARY_DIR}/doc/redis_config_examples/redis_4_0.conf
         DESTINATION ${DATADIR}/doc/openvas-scanner/redis_config_examples/ )

install (DIRECTORY DESTINATION ${OPENVAS_NVT_DIR})

## End

