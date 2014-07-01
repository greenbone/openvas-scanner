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
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
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

add_executable (openvassd attack.c comm.c hosts.c locks.c log.c
                nasl_plugins.c ntp.c openvassd.c otp.c
                piic.c pluginlaunch.c pluginload.c
                pluginscheduler.c plugs_req.c preferences.c
                processes.c save_kb.c sighand.c utils.c)

set_target_properties (openvassd PROPERTIES LINKER_LANGUAGE C)

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

if (OPENVAS_SCANNER_CERTIFICATE)
  add_definitions (-DSCANNERCERT=\\\"${OPENVAS_SCANNER_CERTIFICATE}\\\")
endif (OPENVAS_SCANNER_CERTIFICATE)

if (OPENVAS_SCANNER_KEY)
  add_definitions (-DSCANNERKEY=\\\"${OPENVAS_SCANNER_KEY}\\\")
endif (OPENVAS_SCANNER_KEY)

if (OPENVAS_CLIENT_CERTIFICATE)
  add_definitions (-DCLIENTCERT=\\\"${OPENVAS_CLIENT_CERTIFICATE}\\\")
endif (OPENVAS_CLIENT_CERTIFICATE)

if (OPENVAS_CLIENT_KEY)
  add_definitions (-DCLIENTKEY=\\\"${OPENVAS_CLIENT_KEY}\\\")
endif (OPENVAS_CLIENT_KEY)

if (OPENVAS_CA_CERTIFICATE)
  add_definitions (-DCACERT=\\\"${OPENVAS_CA_CERTIFICATE}\\\")
endif (OPENVAS_CA_CERTIFICATE)

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

if (OPENVAS_PID_DIR)
  add_definitions (-DOPENVAS_PID_DIR=\\\"${OPENVAS_PID_DIR}\\\")
endif (OPENVAS_PID_DIR)

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

target_link_libraries (openvassd
                       "${OPENVAS_LDFLAGS} ${GLIB_LDFLAGS} ${GCRYPT_LDFLAGS} ${GNUTLS_LDFLAGS}")

set_target_properties (openvassd PROPERTIES COMPILE_FLAGS
                       "${OPENVAS_CFLAGS} ${GLIB_CFLAGS} ${GNUTLS_CFLAGS}")

## Tests

enable_testing ()

## Static analysis

add_custom_target (splint COMMENT "Running splint..."
                   COMMAND sh -c \"splint -booltype gboolean -predboolint +unixlib +export-header `pkg-config --cflags glib-2.0` `pkg-config --cflags libopenvas` *.c\")

add_custom_target (rats COMMENT "Running rats..."
                   COMMAND sh -c \"rats --warning 2 *.[ch]\")

add_custom_target (flawfinder COMMENT "Running flawfinder..."
                   COMMAND sh -c \"flawfinder *.[ch]\")

add_custom_target (check COMMENT "Checking code...")
add_dependencies (check splint rats flawfinder)

## Tag files

set (C_FILES "attack.c" "comm.c" "hosts.c" "locks.c" "log.c"
     "nasl_plugins.c" "ntp.c" "openvassd.c" "otp.c"
     "piic.c" "pluginlaunch.c" "pluginload.c"
     "pluginscheduler.c" "plugs_req.c" "preferences.c"
     "processes.c" "save_kb.c" "sighand.c" "utils.c")
add_custom_target (etags COMMENT "Building TAGS..."
                   COMMAND etags ${C_FILES})
add_custom_target (ctags COMMENT "Building tags..."
                   COMMAND ctags ${C_FILES})
add_custom_target (tags COMMENT "Building tags files...")
add_dependencies (tags etags ctags)

## End
