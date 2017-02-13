# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: Tests for the nasl functions bn_random and bn_cmp
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

function test_bn_random()
{
  testcase_start("test_bn_random");

  data = bn_random(need:16);

  # we cannot check the actual data because it's random.  But we can
  # check that we've got 2 bytes.  The first byte of the string may be 0
  # if the most significant bit would be set otherwise.
  if (data[0] == string("\x00"))
    data = substr(data, 1, 2);

  if (strlen(data) == 2)
    testcase_ok();
  else
    {
      testcase_failed();
      display("expected 2 bytes, got ", strlen(data),
	      " (hexdata=", hexstr(data), ")\n");
    }
}

test_bn_random();

function test_bn_cmp(a, b, expected)
{
  local_var result;

  testcase_start(string("test_bn_cmp ", hexstr(a), ", ", hexstr(b)));

  result = bn_cmp(key1:a, key2:b);

  if (result == expected)
    {
      testcase_ok();
    }
  else
    {
      testcase_failed();
      display("expected ", expected, ", got ", result, "\n");
    }
}

test_bn_cmp(a:raw_string(0x00), b:raw_string(0x01), expected:-1);
test_bn_cmp(a:raw_string(0x20), b:raw_string(0x20), expected:0);
test_bn_cmp(a:raw_string(0x10, 0x20), b:raw_string(0x08, 0x20), expected:1);
