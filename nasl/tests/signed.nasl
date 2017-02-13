# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: Test script with a valid signature.
#              If this file is modified the corresponding
#              signature file has to be updated too.
#
# Authors:
# Bernhard Herzog <bernhard.herzog@intevation.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

# Determines whether the script being executed is authenticated.
function display_authentication_status()
{
  local_var s;

  # There doesn't seem to be a built-in way to check the authentication
  # status directly, so we do this by trying to call a function that can
  # only be called when the script is authenticated.  We use file_stat
  # because it meets a number of requirements:
  #  1. Only returns NULL when the script is not authenticated
  #  2. Does not rely on certain files or commands being present on the system
  #  3. Doesn't have side effects.

  s = file_stat("/");

  if (s != NULL)
    {
      display("YES\n");
    }
  else
    {
      display("NO\n");
    }
}

display_authentication_status();
