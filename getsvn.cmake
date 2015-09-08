# getsvn.cmake
# This script attempts to determine the SVN revision and writes or updates
# a "svnrevision.h" file if successful.
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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

find_program (SVN_EXECUTABLE svn DOC "subversion command line client")

macro (Subversion_GET_REVISION dir variable)
  execute_process (COMMAND ${SVN_EXECUTABLE} info ${dir}
    OUTPUT_VARIABLE ${variable}
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  string (REGEX REPLACE "^(.*\n)?Revision: ([^\n]+).*"
    "\\2" ${variable} "${${variable}}")
endmacro (Subversion_GET_REVISION)

if (EXISTS "${SOURCE_DIR}/.svn/" OR EXISTS "${SOURCE_DIR}/../.svn/")
  if (SVN_EXECUTABLE)
    Subversion_GET_REVISION (${SOURCE_DIR} SVN_REVISION)
  endif (SVN_EXECUTABLE)
endif (EXISTS "${SOURCE_DIR}/.svn/" OR EXISTS "${SOURCE_DIR}/../.svn/")

if (SVN_REVISION)
  file (WRITE svnrevision.h.tmp "#define OPENVASSD_SVN_REVISION ${SVN_REVISION}\n")
  execute_process (COMMAND ${CMAKE_COMMAND} -E copy_if_different
                   svnrevision.h.tmp svnrevision.h)
  file (REMOVE svnrevision.h.tmp)
endif (SVN_REVISION)
