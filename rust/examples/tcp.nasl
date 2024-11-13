# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

display("Start");
display("is function defined: ", defined_func("open_sock_tcp"));
sock = open_sock_tcp(34254, transport: 1);
display("was socket created: ", !isnull(sock));
display("fd: ", sock);
ret = send(socket: sock, data: 'foobar');
display("num bytes sent: ", ret);
rec = recv(socket: sock, length: 10, min: 3);
display(rec);
display("end");
