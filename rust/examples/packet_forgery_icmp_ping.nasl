# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 1234,
                     ip_p : 0x01, #IPPROTO_ICMP
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.10);
dump_ip_packet (ip_packet);

icmp = forge_icmp_packet(ip:  ip_packet,
                              icmp_type: 8,
                              icmp_code: 0,
                              icmp_seq:   1,
                              icmp_id:   1,
			      data: "1234");

display(icmp);

send_packet(icmp);
