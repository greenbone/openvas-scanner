# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

# when started with
# nasl-cli execute -p examples/ examples/error.nasl
# it fails on include otherwise on display(a)

include("error_inc.inc");
display(a)
