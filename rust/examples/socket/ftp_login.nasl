# SPDX-FileCopyrightText: 2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

display("Start");
display("is function open_sock_tcp defined: ", defined_func("open_sock_tcp"));
sock = open_sock_tcp(21, transport: 1);
display("was socket created: ", !isnull(sock));
display("fd: ", sock);
display("is function ftp_log_in defined: ", defined_func("ftp_log_in"));
# Login data for ftp://ftp.dlptest.com/ provided by https://dlptest.com/ftp-test/
user = "dlpuser";
pass = "rNrKYTX9g7z3RgJRmxWuGHbeu";
display("login succeeded: ", ftp_log_in(user: user, pass: pass, socket: sock));
close(sock);
display("end");
