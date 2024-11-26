# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

display("Start");
display("is function defined: ", defined_func("open_priv_sock_udp"));
sock = open_priv_sock_udp(dport: 34254);
display("was socket created: ", !isnull(sock));
display("fd: ", sock);
ret = send(socket: sock, data: '123');
display("num bytes sent: ", ret);
rec = recv(socket: sock, length: 10);
display(rec);
close(sock);
display("end");
