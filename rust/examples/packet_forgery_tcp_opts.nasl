# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

ip_packet = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 1234,
                        ip_p : 0x06,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : 192.168.1.6,
                        ip_dst : 192.168.1.1);
tcp_packet = forge_tcp_packet(ip:       ip_packet,
				data: 1234,
                                th_sport: 5080,
                                th_dport: 80,
                                th_seq:   1000,
                                th_ack:   0,
                                th_x2:    0,
                                th_off:   5,
                                th_flags: 33,
                                th_win:   0,
                                th_sum:   0,
                                th_urp:   0);
tcp_packet = insert_tcp_options(tcp: tcp_packet, 3, 10);
opt = get_tcp_option(tcp: tcp_packet, option: 3);
dump_tcp_packet(tcp_packet);
send_packet(tcp_packet);
