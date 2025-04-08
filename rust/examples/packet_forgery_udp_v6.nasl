# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

### For testing local
# sudo ip addr add 5858::1/64 dev wlp6s0 
# sudo ip -6 route add 5858::1 dev wlp6s0 
# sudo target/debug/scannerctl execute script examples/packet_forgery_udp_v6.nasl -t "5858::1
###

IP6_HLIM = 128;

src = "5858::1";
dst = "5858::1";

ip6 = forge_ip_v6_packet( ip6_v: 6, # IP6_v,
                         ip6_p: IPPROTO_UDP, #0x11
                         ip6_hlim:IP6_HLIM,
                         ip6_src: src,
                         ip6_dst: dst);
                         
dump_ip_v6_packet (ip6);

udp6_packet = forge_udp_v6_packet(ip6: ip6,
                              uh_sport: 5080,
                              uh_dport: 80,
                              uh_ulen:   12,
                              uh_sum:   0,
			      data: 1234);

display(get_udp_v6_element(udp:udp6_packet, element:"uh_sport"));

udp6_packet = set_udp_v6_elements(udp: udp6_packet, uh_sport: 33000);

display(get_udp_v6_element(udp:udp6_packet, element:"uh_sport"));

dump_ip_v6_packet (udp6_packet);

send_v6packet(udp6_packet);
