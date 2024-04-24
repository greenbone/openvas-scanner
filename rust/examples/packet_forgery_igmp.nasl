# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 1234,
                     ip_p : 0x02, #IPPROTO_IGMP
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.10);

igmp = forge_igmp_packet(ip:  ip_packet,
                              type: 0x11,
                              code: 10,
                              group:   224.0.0.1,
			      );

display(igmp);
send_packet(igmp);
