# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: prints the test summary
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

function testsuite_summary()
{
  display("----------\n");
  display(num_successful + num_failed, " tests, ", num_failed, " failed\n");

  if (num_failed > 0)
    exit(1);
}

testsuite_summary();
