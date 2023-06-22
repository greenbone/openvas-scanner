# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later

ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : rand(),
#                     ip_p : IPPROTO_TCP, # No implemented
                     ip_p : 0x06,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);
dump_ip_packet (ip_packet);

ip_packet = set_ip_elements(ip: ip_packet, ip_ttl: 127, ip_src: 192.168.0.10);
dump_ip_packet (ip_packet);
elem = get_ip_element(ip: ip_packet, element: "ip_ttl");
display(elem);


tcp_packet = forge_tcp_packet(ip:       ip_packet,
                              th_sport: 5080,
                              th_dport: 80,
                              th_seq:   1000,
                              th_ack:   0,
                              th_x2:    0,
                              th_off:   5,
                              th_flags: TH_SYN,
                              th_win:   0,
                              th_sum:   0,
                              th_urp:   0);

dump_tcp_packet (ip_packet);

