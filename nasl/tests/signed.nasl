# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

# OpenVAS Testsuite for the NASL interpreter
# Description: Test script with a valid signature.
#              If this file is modified the corresponding
#              signature file has to be updated too.

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
