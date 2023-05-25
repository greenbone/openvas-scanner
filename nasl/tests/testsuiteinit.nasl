# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

# OpenVAS Testsuite for the NASL interpreter
# Description: Testsuite support functions

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
