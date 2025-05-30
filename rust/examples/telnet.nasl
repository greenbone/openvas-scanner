# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#set_kb_item(name:"Transports/TCP/23", value: 1);
soc = open_sock_tcp(23);
a = telnet_init(soc);
display (a);
