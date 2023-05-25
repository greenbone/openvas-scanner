# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

# OpenVAS Testsuite for the NASL interpreter
# Description: prints the test summary

function testsuite_summary()
{
  display("----------\n");
  display(num_successful + num_failed, " tests, ", num_failed, " failed\n");

  if (num_failed > 0)
    exit(1);
}

testsuite_summary();
