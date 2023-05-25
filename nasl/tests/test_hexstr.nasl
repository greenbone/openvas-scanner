# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

# OpenVAS Testsuite for the NASL interpreter
# Description: Test routine for the nasl function hexstr

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
