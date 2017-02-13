# OpenVAS Testsuite for the NASL interpreter
# $Id$
# Description: Tests for the nasl functions isotime_*
#
# Authors:
# Werner Koch <wk@gnupg.org>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
# along with this program; if not, see <http://www.gnu.org/licenses/>.

if (!defined_func("testcase_start")) {
  include("testsuiteinit.nasl");
}

function test_isotime_now()
{
  local_var now;

  testcase_start("test_isotime_now");

  now = isotime_now();

  if (strlen(now) == 15)
      testcase_ok();
  else
      testcase_failed();
}

test_isotime_now();


function test_isotime_is_valid(t, e)
{
  local_var result;

  testcase_start(string("test_isotime_is_valid(",t,", ", e, ")"));

  result = isotime_is_valid(t);

  if (result == e)
      testcase_ok();
  else
      testcase_failed();
}

test_isotime_is_valid(t:"", e:0);
test_isotime_is_valid(t:"a8691002T123456", e:0);
test_isotime_is_valid(t:"18691002T123456", e:1);
test_isotime_is_valid(t:"18691002T12345", e:0);
test_isotime_is_valid(t:"18691002T1234512", e:0);
test_isotime_is_valid(t:"1869-10-02 12:34:56", e:1);
test_isotime_is_valid(t:"1869-10-02 12:34", e:1);
test_isotime_is_valid(t:"1869-10-02 12", e:1);
test_isotime_is_valid(t:"1869-10-02T12:34:56", e:0);


function test_isotime_scan(t, e)
{
  local_var result;

  testcase_start(string("test_isotime_scan(",t,", ", e, ")"));

  result = isotime_scan(t);

  if (result == e)
      testcase_ok();
  else
      testcase_failed();
}

test_isotime_scan(t:NULL, e:NULL);
test_isotime_scan(t:"", e:NULL);
test_isotime_scan(t:"a8691002T123456", e:NULL);
test_isotime_scan(t:"18691002T123456", e:"18691002T123456");
test_isotime_scan(t:"18691002T12345", e:NULL);
test_isotime_scan(t:"18691002T1234512", e:NULL);
test_isotime_scan(t:"1869-10-02 12:34:56", e:"18691002T123456");
test_isotime_scan(t:"1869-10-02 12:34", e:"18691002T123400");
test_isotime_scan(t:"1869-10-02 12", e:"18691002T120000");
test_isotime_scan(t:"1869-10-02T12:34:56", e:NULL);


function test_isotime_print(t, e)
{
  local_var result;

  testcase_start(string("test_isotime_print(",t,", ", e, ")"));

  result = isotime_print(t);

  if (result == e)
      testcase_ok();
  else {
      testcase_failed();
  }
}

test_isotime_print(t:NULL, e:"[none]");
test_isotime_print(t:"", e:"[none]");
test_isotime_print(t:"a8691002T123456", e:"[none]");
test_isotime_print(t:"18691002T123456", e:"1869-10-02 12:34:56");
test_isotime_print(t:"18691002T12345", e:"[none]");
test_isotime_print(t:"18691002T1234512", e:"1869-10-02 12:34:51");
test_isotime_print(t:"1869-10-02 12:34:56", e:"[none]");
test_isotime_print(t:"1869-10-02 12:34", e:"[none]");
test_isotime_print(t:"1869-10-02 12", e:"[none]");
test_isotime_print(t:"1869-10-02T12:34:56", e:"[none]");


function test_isotime_add(t, e, n, s)
{
  local_var result;

  testcase_start(string("test_isotime_add(",t,", ", e, ")"));

  if (!isnull(n) && !isnull(s))
      result = isotime_add(t, days:n, seconds:s);
  else if (!isnull(n))
      result = isotime_add(t, days:n);
  else if (!isnull(s))
      result = isotime_add(t, seconds:s);
  else
      result = isotime_add(t);
# note: We don't yet test things like: isotime_add(t days:NULL)

  if (result == e)
      testcase_ok();
  else {
      testcase_failed();
      display("result-->", result, "<---\n");
  }
}

test_isotime_add(t:NULL, n:NULL, s:NULL, e:NULL);
test_isotime_add(t:"",  n:NULL, s:NULL, e:NULL);
test_isotime_add(t:"18691002T120000", n:NULL, s:NULL, e:"18691002T120000");
test_isotime_add(t:"18691002T120000", n:0, s:NULL, e:"18691002T120000");
test_isotime_add(t:"18691002T120000", n:NULL, s:0, e:"18691002T120000");
test_isotime_add(t:"18691002T120000", n:0, s:0, e:"18691002T120000");
test_isotime_add(t:"18691002T120000", n:-1, s:0, e:NULL);
test_isotime_add(t:"18691002T120000", n:0, s:-1, e:NULL);
test_isotime_add(t:"18691002T120000", n:0, s:1,      e:"18691002T120001");
test_isotime_add(t:"18691002T120000", n:0, s:86400,  e:"18691003T120000");
test_isotime_add(t:"19000228T120000", n:1, s:0,  e:"19000301T120000");
test_isotime_add(t:"20000228T120000", n:1, s:0,  e:"20000229T120000");
test_isotime_add(t:"20000228T120000", n:1, s:1,  e:"20000229T120001");
test_isotime_add(t:"20000101T000000", n:1, s:1,  e:"20000102T000001");
test_isotime_add(t:"20000101T000000", n:1, s:1,  e:"20000102T000001");
test_isotime_add(t:"15821015T000000", n:0, s:0,  e:"15821015T000000");
test_isotime_add(t:"15821005T000000", n:0, s:0,  e:NULL);
# Dates before the Gregorian calendar switch are not yet supported, thus:
test_isotime_add(t:"15821004T000000", n:0, s:0,  e:NULL);

#eof