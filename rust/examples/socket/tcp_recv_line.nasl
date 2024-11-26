# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

display("Start");
display("is function defined: ", defined_func("open_sock_udp"));
sock = open_sock_tcp(34254, transport: 1);
if (isnull(sock)) {
  display("Failed to open socket");
  exit(0);
}
display("fd: ", sock);
ret = send(socket: sock, data: '123');
if (ret < 0) {
  display("Failed to send data");
  exit(0);
}
display("num bytes sent: ", ret);
rec = recv_line(socket: sock, length: 10, timeout: 1);
display("line1: ", rec);
rec = recv_line(socket: sock, length: 10, timeout: 1);
display("line2: ", rec);
rec = recv_line(socket: sock, length: 10, timeout: 1);
display("line3: ", rec);
display("end");
