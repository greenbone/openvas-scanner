# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 1234,
                     ip_p : 0x11, # IPPROTO_UDP
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.10);
dump_ip_packet (ip_packet);

udp_packet = forge_udp_packet(ip:       ip_packet,
                              uh_sport: 5080,
                              uh_dport: 80,
                              uh_len:   8,
                              th_sum:   0,
			      data: "1234");
display(get_udp_element(udp:udp_packet, element:"uh_sport"));
udp_packet = set_udp_elements(udp: udp_packet, uh_sport: 33000);
display(get_udp_element(udp:udp_packet, element:"uh_sport"));
dump_ip_packet (udp_packet);

send_packet(udp_packet);
