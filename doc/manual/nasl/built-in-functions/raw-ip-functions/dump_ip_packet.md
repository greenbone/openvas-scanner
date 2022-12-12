# dump_ip_packet

## NAME

**dump_ip_packet** - dumps IP datagrams.

## SYNOPSIS

*any* **dump_ip_packet**(*string*, ...);

**dump_ip_packet** It takes any number of unnamed (string) arguments.


## DESCRIPTION

Receive a list of IP packets and print them in a readable format in the screen.

## RETURN VALUE

Return always FAKE_CELL;

## EXAMPLES

**1** :
```cpp
ip_packet = forge_ip_packet(ip_hl:  5,
                            ip_v:   4,
                            ip_tos: 0,
                            ip_id:  rand(),
                            ip_off: IP_DF,
                            ip_ttl: 64,
                            ip_p:   IPPROTO_TCP,
                            ip_sum: 0,
                            ip_src: 192.168.0.1,
                            ip_dst: 192.168.0.12);

dump_ip_packet (ip_packet);
```

## SEE ALSO

**[dump_ip_packet(3)](dump_ip_packet.md)**, **[dump_tcp_packet(3)](dump_tcp_packet.md)**, **[dump_udp_packet(3)](dump_udp_packet.md)**, **[dump_icmp_packet(3)](dump_icmp_packet.md)**, **[forge_icmp_packet(3)](forge_icmp_packet.md)**, **[forge_igmp_packet(3)](forge_igmp_packet.md)**, **[forge_ip_packet(3)](forge_ip_packet.md)**, **[forge_tcp_packet(3)](forge_tcp_packet.md)**, **[forge_udp_packet(3)](forge_udp_packet.md)**, **[get_icmp_element(3)](get_icmp_element.md)**, **[get_ip_element(3)](get_ip_element.md)**, **[get_tcp_element(3)](get_tcp_element.md)**, **[get_udp_element(3)](get_udp_element.md)**, **[insert_ip_options(3)](insert_ip_options.md)**, **[pcap_next(3)](pcap_next.md)**, **[set_ip_elements(3)](set_ip_elements.md)**, **[set_tcp_elements(3)](set_tcp_elements.md)**, **[insert_tcp_options(3)](insert_tcp_options.md)**, **[get_tcp_options(3)](get_tcp_options.md)**, **[set_udp_elements(3)](set_udp_elements.md)**, **[send_packet(3)](send_packet.md)**, **[forge_ipv6_packet(3)](forge_ipv6_packet.md)**, **[get_ipv6_element(3)](get_ipv6_element.md)**, **[set_ipv6_elements(3)](set_ipv6_elements.md)**, **[dump_ipv6_packet(3)](dump_ipv6_packet.md)**, **[insert_ipv6_options(3)](insert_ipv6_options.md)**, **[forge_tcp_v6_packet(3)](forge_tcp_v6_packet.md)**, **[get_tcp_v6_element(3)](get_tcp_v6_element.md)**, **[set_tcp_v6_elements(3)](set_tcp_v6_elements.md)**, **[insert_tcp_v6_options(3)](insert_tcp_v6_options.md)**, **[get_tcp_v6_options(3)](get_tcp_v6_options.md)**, **[dump_tcp_v6_packet(3)](dump_tcp_v6_packet.md)**, **[tcp_v6_ping(3)](tcp_v6_ping.md)**, **[forge_udp_v6_packet(3)](forge_udp_v6_packet.md)**, **[get_udp_v6_element(3)](get_udp_v6_element.md)**, **[set_udp_v6_elements(3)](set_udp_v6_elements.md)**, **[dump_udp_v6_packet(3)](dump_udp_v6_packet.md)**, **[forge_icmp_v6_packet(3)](forge_icmp_v6_packet.md)**, **[get_icmp_v6_element(3)](get_icmp_v6_element.md)**, **[dump_icmp_v6_packet(3)](dump_icmp_v6_packet.md)**, **[forge_igmp_v6_packet(3)](forge_igmp_v6_packet.md)**, **[send_v6packet(3)](send_v6packet.md)**, **[send_capture (3)](send_capture .md)**, **[get_local_mac_address_from_ip(3)](get_local_mac_address_from_ip.md)**, **[send_arp_request(3)](send_arp_request.md)**, **[forge_frame(3)](forge_frame.md)**, **[send_frame(3)](send_frame.md)**, **[dump_frame(3)](dump_frame.md)**
