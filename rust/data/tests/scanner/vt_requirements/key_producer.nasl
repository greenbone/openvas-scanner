# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

if (description)
{
  script_oid("0.0.0.0.0.0.0.0.1.0");
  exit(0);
}

set_kb_item(name: "present_key", value: 1);
log_message(data: "producer ran");
