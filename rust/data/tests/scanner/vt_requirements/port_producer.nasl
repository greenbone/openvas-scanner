# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

if (description)
{
  script_oid("0.0.0.0.0.0.0.0.2.0");
  exit(0);
}

scanner_add_port(port: 20);
scanner_add_port(port: 2000, proto: "udp");
set_kb_item(name: "Ports/tcp/22", value: 0);
set_kb_item(name: "Ports/udp/2002", value: 0);
log_message(data: "port producer ran");
