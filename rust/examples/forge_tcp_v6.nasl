# SPDX-FileCopyrightText: 2023 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

# This script forges an IPv6 packet with a TCP segment including data. Sends it and captures the packet.
# For running with openvas-nasl and scannerctl, run the following commands respectively
#    sudo openvas-nasl -X -d -i $PLUGINSPATH ~/my_nasl/forge_tcp_v6.nasl -t 5858::2
#    sudo target/debug/scannerctl execute script ~/my_nasl/forge_tcp_v6.nasl -t 5858::2
#
# Set the correct IPv6 addresses and routes in the origin and destination hosts with the right address on each.
#    sudo ip addr add 5858::1/64 dev wlp6s0 
#    sudo ip -6 route add 5858::1 dev wlp6s0 

if(description) {
  script_oid("1.2.3");
  exit(0);
}

include("misc_func.inc");


src = "5858::1";
dst = "5858::2";
sport = 63321;
dport = 63322;

filter = string("tcp and src ", src, " and dst ", dst);

ip6 = forge_ip_v6_packet( ip6_v: 6, # IP6_v,
                         ip6_p: 6, #IP6_P,
                         ip6_plen:40,
                         ip6_hlim:IP6_HLIM,
                         ip6_src: src,
                         ip6_dst: dst);


tcp = forge_tcp_v6_packet(ip6       : ip6,
                       th_ack   : 0,
                       th_dport : dport,
                       th_flags : TH_SYN,
                       #th_seq   : tcp_seq + 1024,
                       th_sport : sport,
                       th_x2    : 0,
                       th_off   : 5,
                       th_win   : 1024,
                       th_urp   : 0,
                       tcp_opt  : 3,
                       tcp_opt_val  : 7,
                       data: "123456",
                       update_ip_len: TRUE
                       );

dump_tcp_v6_packet(tcp);
                      
res = send_v6packet(tcp, pcap_filter: filter, pcap_timeout: 20, pcap_active: TRUE);
display(res);
