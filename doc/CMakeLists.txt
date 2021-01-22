# Copyright (C) 2011-2021 Greenbone Networks GmbH
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

## build

include (FindDoxygen)

if (NOT DOXYGEN_EXECUTABLE)
  message (STATUS "WARNING: Doxygen is required to build the HTML docs.")
else (NOT DOXYGEN_EXECUTABLE)
  add_custom_target (doc COMMENT "Building documentation..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/.built-html)

  add_custom_command (OUTPUT .built-html
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-html\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

  add_custom_target (doc-full COMMENT "Building documentation..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full ${CMAKE_CURRENT_BINARY_DIR}/.built-html_full)

  add_custom_command (OUTPUT .built-html_full
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-html_full\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_full)

  add_custom_target (doc-xml COMMENT "Building documentation (XML)..."
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml ${CMAKE_CURRENT_BINARY_DIR}/.built-xml)

  add_custom_command (OUTPUT .built-xml
    COMMAND sh
    ARGS -c \"${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml && touch ${CMAKE_CURRENT_BINARY_DIR}/.built-xml\;\"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_xml)
endif (NOT DOXYGEN_EXECUTABLE)
