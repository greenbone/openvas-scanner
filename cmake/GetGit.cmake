# Copyright (C) 2018-2021 Greenbone Networks GmbH
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

# This script attempts to determine the Git commit ID and writes or updates
# a "gitrevision.h" file if successful.

find_package (Git)

macro (Git_GET_REVISION dir variable)
  execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
                  WORKING_DIRECTORY ${dir}
                  OUTPUT_VARIABLE GIT_BRANCH
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process(COMMAND ${GIT_EXECUTABLE} log -1 --format=%h
                  WORKING_DIRECTORY ${dir}
                  OUTPUT_VARIABLE GIT_COMMIT_HASH
                  OUTPUT_STRIP_TRAILING_WHITESPACE)
  string (REPLACE "/" "_" GIT_BRANCH ${GIT_BRANCH})
  set (${variable} "${GIT_COMMIT_HASH}-${GIT_BRANCH}")
endmacro (Git_GET_REVISION)

if (EXISTS "${SOURCE_DIR}/.git/")
  if (GIT_FOUND)
    Git_GET_REVISION (${SOURCE_DIR} GIT_REVISION)
  endif (GIT_FOUND)
endif (EXISTS "${SOURCE_DIR}/.git/")

if (GIT_REVISION)
  file (WRITE gitrevision.h.in "#define OPENVASSD_GIT_REVISION \"${GIT_REVISION}\"\n")
  execute_process (COMMAND ${CMAKE_COMMAND} -E copy_if_different
                   gitrevision.h.in gitrevision.h)
  file (REMOVE gitrevision.h.in)
endif (GIT_REVISION)
