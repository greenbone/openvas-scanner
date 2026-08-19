# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

if (description)
{
  script_oid("0.0.0.0.0.0.0.0.1.1");
  script_dependencies("key_producer.nasl");
  script_require_keys("present_key");
  exit(0);
}

log_message(data: "this should be visible");
