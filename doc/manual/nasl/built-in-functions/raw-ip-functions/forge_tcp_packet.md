# forge_tcp_packet

## NAME

**forge_tcp_packet** - Fills an IP datagram with TCP data.

## SYNOPSIS

*any* **forge_tcp_packet**(data: *string*, ip: *string*, th_ack: *int*, th_dport: *int*, th_flags: *TCP_HEADER_FLAG*, th_off: *int*, th_seq: *int*, th_sport: *int*, th_sum: *int*, th_urp: *int*, th_win: *int*, th_x2: *int*, update_ip_len: *int*);

**forge_tcp_packet** It takes many named arguments, someones are optionals. For details, seethe description below.


## DESCRIPTION

Fills an IP datagram with TCP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:

- data: is the TCP data payload.
- ip: is the IP datagram to be filled.
- th_ack: is the acknowledge number. NASL will convert it into network order if necessary. 0 by default.
- th_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
- th_flags: are the TCP flags. 0 by default.
- th_off: is the size of the TCP header in 32 bits words. By default, 5.
- th_seq: is the TCP sequence number. NASL will convert it into network order if necessary. Random by default.
- th_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
- th_sum: is the TCP checksum. By default, the right value is computed.
- th_urp: is the urgent pointer. 0 by default.
- th_win: is the TCP window size. NASL will convert it into network order if necessary. 0 by default.
- th_x2: is a reserved field and should probably be left unchanged. 0 by default.
- update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.


## RETURN VALUE

The modified IP datagram or NULL on error.

## ERRORS

- You must supply the 'ip' argument: You get this error if you don't provide the named arugment `ip`.


## EXAMPLES

**1** Dump the forged tcp packet:
```cpp
ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_TCP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);


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
```

## SEE ALSO

**[dump_ip_packet(3)](dump_ip_packet.md)**, **[dump_tcp_packet(3)](dump_tcp_packet.md)**, **[dump_udp_packet(3)](dump_udp_packet.md)**, **[dump_icmp_packet(3)](dump_icmp_packet.md)**, **[forge_icmp_packet(3)](forge_icmp_packet.md)**, **[forge_igmp_packet(3)](forge_igmp_packet.md)**, **[forge_ip_packet(3)](forge_ip_packet.md)**, **[forge_tcp_packet(3)](forge_tcp_packet.md)**, **[forge_udp_packet(3)](forge_udp_packet.md)**, **[get_icmp_element(3)](get_icmp_element.md)**, **[get_ip_element(3)](get_ip_element.md)**, **[get_tcp_element(3)](get_tcp_element.md)**, **[get_udp_element(3)](get_udp_element.md)**, **[insert_ip_options(3)](insert_ip_options.md)**, **[pcap_next(3)](pcap_next.md)**, **[set_ip_elements(3)](set_ip_elements.md)**, **[set_tcp_elements(3)](set_tcp_elements.md)**, **[insert_tcp_options(3)](insert_tcp_options.md)**, **[get_tcp_options(3)](get_tcp_options.md)**, **[set_udp_elements(3)](set_udp_elements.md)**, **[send_packet(3)](send_packet.md)**, **[forge_ipv6_packet(3)](forge_ipv6_packet.md)**, **[get_ipv6_element(3)](get_ipv6_element.md)**, **[set_ipv6_elements(3)](set_ipv6_elements.md)**, **[dump_ipv6_packet(3)](dump_ipv6_packet.md)**, **[insert_ipv6_options(3)](insert_ipv6_options.md)**, **[forge_tcp_v6_packet(3)](forge_tcp_v6_packet.md)**, **[get_tcp_v6_element(3)](get_tcp_v6_element.md)**, **[set_tcp_v6_elements(3)](set_tcp_v6_elements.md)**, **[insert_tcp_v6_options(3)](insert_tcp_v6_options.md)**, **[get_tcp_v6_options(3)](get_tcp_v6_options.md)**, **[dump_tcp_v6_packet(3)](dump_tcp_v6_packet.md)**, **[tcp_v6_ping(3)](tcp_v6_ping.md)**, **[forge_udp_v6_packet(3)](forge_udp_v6_packet.md)**, **[get_udp_v6_element(3)](get_udp_v6_element.md)**, **[set_udp_v6_elements(3)](set_udp_v6_elements.md)**, **[dump_udp_v6_packet(3)](dump_udp_v6_packet.md)**, **[forge_icmp_v6_packet(3)](forge_icmp_v6_packet.md)**, **[get_icmp_v6_element(3)](get_icmp_v6_element.md)**, **[dump_icmp_v6_packet(3)](dump_icmp_v6_packet.md)**, **[forge_igmp_v6_packet(3)](forge_igmp_v6_packet.md)**, **[send_v6packet(3)](send_v6packet.md)**, **[send_capture (3)](send_capture .md)**, **[get_local_mac_address_from_ip(3)](get_local_mac_address_from_ip.md)**, **[send_arp_request(3)](send_arp_request.md)**, **[forge_frame(3)](forge_frame.md)**, **[send_frame(3)](send_frame.md)**, **[dump_frame(3)](dump_frame.md)**
