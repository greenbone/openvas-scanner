# OpenVAS
# $Id$
# Description: CMakefile for the OpenVAS Scanner program
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

add_executable (openvassd attack.c comm.c hosts.c log.c
                nasl_plugins.c ntp.c openvassd.c otp.c
                pluginlaunch.c pluginload.c
                pluginscheduler.c plugs_req.c
                processes.c sighand.c utils.c)

set_target_properties (openvassd PROPERTIES LINKER_LANGUAGE C)

include_directories (${GLIB_INCLUDE_DIRS} ${LIBOPENVAS_NASL_INCLUDE_DIRS}
                     ${LIBOPENVAS_BASE_INCLUDE_DIRS}
                     ${LIBOPENVAS_MISC_INCLUDE_DIRS})

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  # If we got SVN_REVISION at configure time,
  # assume we can get it at build time as well
  if (SVN_REVISION)
    # a custom target that is always built
    add_custom_target (revisiontag ALL)

    # creates svnversion.h using cmake script
    add_custom_command (TARGET revisiontag COMMAND ${CMAKE_COMMAND}
                        -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
                        -P ${CMAKE_SOURCE_DIR}/getsvn.cmake)

    # explicitly say that the executable depends on custom target
    add_dependencies (openvassd revisiontag)

    # include the output directory, where the svnversion.h file is generated
    include_directories (${CMAKE_CURRENT_BINARY_DIR})
    add_definitions (-DSVN_REV_AVAILABLE)
  endif (SVN_REVISION)
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

if (OPENVASSD_VERSION)
  add_definitions (-DOPENVASSD_VERSION=\\\"${OPENVASSD_VERSION}\\\")
endif (OPENVASSD_VERSION)

add_definitions (-DPREFIX=\\\"${CMAKE_INSTALL_PREFIX}\\\")

if (OPENVAS_NVT_DIR)
  add_definitions (-DOPENVAS_NVT_DIR=\\\"${OPENVAS_NVT_DIR}\\\")
endif (OPENVAS_NVT_DIR)

if (OPENVAS_CACHE_DIR)
  add_definitions (-DOPENVAS_CACHE_DIR=\\\"${OPENVAS_CACHE_DIR}\\\")
endif (OPENVAS_CACHE_DIR)

if (OPENVAS_LOG_DIR)
  add_definitions (-DOPENVAS_LOG_DIR=\\\"${OPENVAS_LOG_DIR}\\\")
endif (OPENVAS_LOG_DIR)

if (OPENVASSD_MESSAGES)
  add_definitions (-DOPENVASSD_MESSAGES=\\\"${OPENVASSD_MESSAGES}\\\")
endif (OPENVASSD_MESSAGES)

if (OPENVASSD_DEBUGMSG)
  add_definitions (-DOPENVASSD_DEBUGMSG=\\\"${OPENVASSD_DEBUGMSG}\\\")
endif (OPENVASSD_DEBUGMSG)

if (OPENVASSD_CONF)
  add_definitions (-DOPENVASSD_CONF=\\\"${OPENVASSD_CONF}\\\")
endif (OPENVASSD_CONF)

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_RUN_DIR)
  add_definitions (-DOPENVAS_RUN_DIR=\\\"${OPENVAS_RUN_DIR}\\\")
endif (OPENVAS_RUN_DIR)

if (SYSCONFDIR)
  add_definitions (-DSYSCONFDIR=\\\"${SYSCONFDIR}\\\")
endif (SYSCONFDIR)

if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")
endif (OPENVAS_SYSCONF_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR=\\\"${OPENVAS_DATA_DIR}\\\")
endif (OPENVAS_DATA_DIR)

if (NVT_TIMEOUT)
  add_definitions (-DNVT_TIMEOUT=${NVT_TIMEOUT})
endif (NVT_TIMEOUT)

if (SCANNER_NVT_TIMEOUT)
  add_definitions (-DSCANNER_NVT_TIMEOUT=${SCANNER_NVT_TIMEOUT})
endif (SCANNER_NVT_TIMEOUT)

target_link_libraries (openvassd ${LIBOPENVAS_NASL_LDFLAGS}
                       ${LIBOPENVAS_BASE_LDFLAGS} ${LIBOPENVAS_MISC_LDFLAGS}
                       ${GLIB_LDFLAGS} ${GCRYPT_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS})

## Tests

enable_testing ()

## Static analysis

add_custom_target (cppcheck COMMENT "Running cppcheck..."
                   COMMAND sh -c \"cppcheck ${CMAKE_CURRENT_SOURCE_DIR}\")

add_custom_target (check COMMENT "Checking code...")
add_dependencies (check cppcheck)

## Tag files

set (C_FILES "attack.c" "comm.c" "hosts.c" "log.c"
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

## End
