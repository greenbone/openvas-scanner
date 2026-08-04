# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

if (description)
{
  script_oid("0.0.0.0.0.0.0.0.2.5");
  script_dependencies("port_producer.nasl");
  script_require_ports("20");
  script_require_udp_ports("2002");
  exit(0);
}

log_message(data: "this should not be visible");
