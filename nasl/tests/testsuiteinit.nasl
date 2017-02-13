# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: Testsuite support functions
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

# initializes the test suite and provides some helper functions

global_var num_successful, num_failed;

num_successful = 0;
num_failed = 0;

function testcase_start(name)
{
  name = _FCT_ANON_ARGS[0];
  display(name, " ");
}

function testcase_ok()
{
  display("OK\n");
  num_successful += 1;
}

function testcase_failed()
{
  display("FAILED\n");
  num_failed += 1;
}
