# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: Test routine for the nasl function hexstr
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
#

function check_hexstr(name, expected, binary)
{
  local_var hexval;

  testcase_start(name);

  hexval = hexstr(binary);
  if (hexval == expected)
    {
      testcase_ok();
    }
  else
    {
      testcase_failed();
      display("expected: ", expected, "\n");
      display("got:      ", hexval, "\n");
    }
}

function check_hexstr_null()
{
  local_var hexval;

  testcase_start("test_hexstr NULL");

  hexval = hexstr(NULL);
  if (isnull(hexval))
    {
      testcase_ok();
    }
  else
    {
      testcase_failed();
      display("hexstr(NULL) did not return NULL\n");
    }
}


check_hexstr(name:"test_hexstr",
	     binary:raw_string(0x01, 0X20, 0XFF, 0x7F, 0x80),
	     expected:"0120ff7f80");
check_hexstr(name:"test_hexstr empty string",
	     binary:"",
	     expected:"");
check_hexstr_null();
