# OpenVAS
# $Id$
# Description: CMakefile for the OpenVAS Scanner documentation
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

## build

set_directory_properties (PROPERTIES CLEAN_NO_CUSTOM true)
set_directory_properties (PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ".built-html;.built-html_full")

include (FindDoxygen)

if (NOT DOXYGEN_EXECUTABLE)
  message (STATUS "WARNING: Doxygen is required to build the HTML docs.")
else (NOT DOXYGEN_EXECUTABLE)
  set (DOC_FILES
    ../src/attack.c ../src/auth.c ../src/comm.c ../src/hosts.c
    ../src/locks.c ../src/log.c ../src/nasl_plugins.c ../src/ntp_11.c
    ../src/openvassd.c ../src/otp_1_0.c ../src/oval_plugins.c ../src/parser.c
    ../src/piic.c ../src/pluginlaunch.c ../src/pluginload.c
    ../src/pluginscheduler.c ../src/plugs_hash.c ../src/plugs_req.c
    ../src/preferences.c ../src/processes.c ../src/rules.c ../src/save_kb.c
    ../src/sighand.c ../src/users.c ../src/utils.c
    ../README ../INSTALL)

  add_custom_target (doc COMMENT "Building documentation..."
    DEPENDS Doxyfile .built-html)

  add_custom_target (doc-full COMMENT "Building documentation..."
    DEPENDS Doxyfile_full .built-html_full)
endif (NOT DOXYGEN_EXECUTABLE)

add_custom_command (OUTPUT .built-html
                    COMMAND sh
					ARGS -c \"cd .. && ${DOXYGEN_EXECUTABLE} doc/Doxyfile && touch doc/.built-html\;\"
					DEPENDS Doxyfile ${DOC_FILES})

add_custom_command (OUTPUT .built-html_full
                    COMMAND sh
					ARGS -c \"cd .. && ${DOXYGEN_EXECUTABLE} doc/Doxyfile_full && touch doc/.built-html_full\;\"
					DEPENDS Doxyfile_full ${DOC_FILES})

