# OpenVAS-libraries/misc
# $Id$
# Description: Makefile for misc of OpenVAS-libraries.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
#
# Copyright:
# Copyright (C) 2010, 2011 Greenbone Networks GmbH
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

## Pass-throughs

include_directories (${GLIB_INCLUDE_DIRS}
                     ${LIBGVM_BASE_INCLUDE_DIRS}
                     ${GNUTLS_INCLUDE_DIRS})

if (MINGW)
  if (CROSS_ENV)
    include_directories (${CROSS_ENV}/include)
    include_directories (${CROSS_ENV}/include/glib-2.0)
    include_directories (${CROSS_ENV}/lib/glib-2.0/include)
  else (CROSS_ENV)
    message (FATAL_ERROR "Could not find include path for WIN32. Consider"
             " building with -DCROSS_ENV=path/to win32/environment")
  endif (CROSS_ENV)
endif (MINGW)

# Library


if (NOT MINGW)
  # On windows we are always PIC and stack-protector is replaces by DEP
  # Also stack protection needs a shared library to work
  set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")
  set (CMAKE_C_FLAGS_RELEASE      "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS}")
endif (NOT MINGW)

if (MINGW)
else (MINGW)
  set (FILES arglists.c bpf_share.c ftp_funcs.c ids_send.c
             network.c plugutils.c popen.c  www_funcs.c pcap.c)

  set (HEADERS arglists.h bpf_share.h ftp_funcs.h scanneraux.h
               network.h pcap_openvas.h plugutils.h popen.h
               nvt_categories.h internal_com.h www_funcs.h)
endif (MINGW)

# Indentation targets
# TODO: Commented out as it provokes error. Unclear
# what this directive is good for.
#add_custom_indent_targets (${FILES})

if (BUILD_STATIC)
  add_library (openvas_misc_static STATIC ${FILES})

  set_target_properties (openvas_misc_static PROPERTIES OUTPUT_NAME "openvas_misc")
  set_target_properties (openvas_misc_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_misc_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
  target_link_libraries (openvas_misc_static)
endif (BUILD_STATIC)

if (BUILD_SHARED)
  add_library (openvas_misc_shared SHARED ${FILES})

  set_target_properties (openvas_misc_shared PROPERTIES OUTPUT_NAME "openvas_misc")
  set_target_properties (openvas_misc_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
  set_target_properties (openvas_misc_shared PROPERTIES SOVERSION "${PROJECT_VERSION_MAJOR}")
  set_target_properties (openvas_misc_shared PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  set_target_properties (openvas_misc_shared PROPERTIES PUBLIC_HEADER "${HEADERS}")

  if (MINGW)
    set (GLIB_LDFLAGS -Wl,--start-group ${GLIB_LDFLAGS} gmodule-2.0 -Wl,--end-group)
    set (W32LIBS ${GLIB_LDFLAGS} gnutls intl iconv tasn1
       gcrypt gpgme assuan libgpg-error ole32 ws2_32 ffi z shlwapi dnsapi winmm)
    target_link_libraries (openvas_misc_shared ${W32LIBS})
  else (MINGW)
    target_link_libraries (openvas_misc_shared LINK_PRIVATE ${GNUTLS_LDFLAGS} ${UUID_LDFLAGS}
                           ${GLIB_LDFLAGS} ${PCAP_LDFLAGS}
                           ${GCRYPT_LDFLAGS} ${LINKER_HARDENING_FLAGS})
  endif (MINGW)
endif (BUILD_SHARED)

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR=\\\"${OPENVAS_DATA_DIR}\\\")
endif (OPENVAS_DATA_DIR)

# @todo Why is this definition setting guarded? OPENVAS_SYSCONF_DIR should
#       always be set.
#$(COMPILE) -DOPENVAS_STATE_DIR=\"$(localstatedir)\" -DCONF_DIR=\"$(sysconfdir)\" -c services1.c
if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")
endif (OPENVAS_SYSCONF_DIR)

# install library

if (BUILD_STATIC)
  install (TARGETS openvas_misc_static
           RUNTIME DESTINATION ${BINDIR}
           ARCHIVE DESTINATION ${LIBDIR}
           PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/misc")
endif (BUILD_STATIC)
if (BUILD_SHARED)
  install (TARGETS openvas_misc_shared
           RUNTIME DESTINATION ${BINDIR}
           LIBRARY DESTINATION ${LIBDIR}
           ARCHIVE DESTINATION ${LIBDIR}
           PUBLIC_HEADER DESTINATION "${INCLUDEDIR}/openvas/misc")
endif (BUILD_SHARED)
