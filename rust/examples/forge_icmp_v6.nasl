# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

if(description) {
  script_oid("1.2.3");
  exit(0);
}

include("misc_func.inc");

# ICMPv6
IP6_v = 0x60;
IP6_P = 0x3a;#ICMPv6
IP6_HLIM = 0x40;
ICMP_ID = rand() % 65536;

ori = "5858::1";
dst = "5858::1";

ip6_packet = forge_ip_v6_packet( ip6_v: 6, # IP6_v,
                                ip6_p: IP6_P,
                                ip6_plen:40,
                                ip6_hlim:IP6_HLIM,
                                ip6_src: ori,
                                ip6_dst: dst );

dump_ip_v6_packet(ip6_packet);

d = "123456";
icmp = forge_icmp_v6_packet( ip6:ip6_packet,
                             icmp_type:128,
                             icmp_code:1,
                             icmp_seq:2,
                             icmp_id:ICMP_ID,
                             icmp_cksum: 0
                             );
dump_icmp_v6_packet(icmpv6);
filter = string("icmp6");
ret = send_v6packet( icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout: 2);
display(ret);
