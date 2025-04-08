# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

ip6_packet = forge_ip_v6_packet( ip6_v: 6,
                                ip6_p: 0x06,
                                ip6_hlim: 128,
                                ip6_src: "5858::1",
                                ip6_dst: "5858::1");

dump_ip_v6_packet(ip6_packet);

tcp6_packet = forge_tcp_v6_packet(ip6:       ip6_packet,
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
dump_tcp_v6_packet(tcp6_packet);

send_v6packet(tcp6_packet);

tcp6_packet = set_tcp_v6_elements(tcp: tcp6_packet, th_sport: 33000);
get_tcp_v6_element(tcp:tcp6_packet, element:"th_sport");
##tcp_packet_opts = insert_tcp_v6_options(tcp: tcp6_packet, 3, 2);
##opt = get_tcp_v6_option(tcp: tcp_packet_opts, option: 3);

#dump_tcp_v6_packet(tcp_packet_opts);

