# forge_ip_packet

## NAME

**forge_ip_packet** - Forge an IP datagram inside the block of data

## SYNOPSIS

*any* **forge_ip_packet**(data: *string*, ip_hl: *int*, ip_id: *int*, ip_len: *int*, ip_off: *int*, ip_p: *IPPROTO*, ip_dst: *string* ,ip_src: *string*, ip_sum: *int*, ip_tos: *int*, ip_ttl: *int*, ip_v is: **);

**forge_ip_packet** It takes named arguments.


## DESCRIPTION
Forge an IP datagram inside the block of data. It takes following arguments:

- data: is the payload.
- ip_hl: is the IP header length in 32 bits words. 5 by default.
- ip_id: is the datagram ID; by default, it is random.
- ip_len: is the length of the datagram. By default, it is 20 plus the length of the data field.
- ip_off: is the fragment offset in 64 bits words. By default, 0.
- ip_p: is the IP protocol. 0 by default.
- ip_src: is the source address in ASCII. NASL will convert it into an integer in network order.
- ip_dst: is the destination address in ASCII. NASL will convert it into an integer in network order. By default it takes the target IP address via call to **[plug_get_host_ip(3)](plug_get_host_ip.md)**. This option looks dangerous, but since anybody can edit an IP packet with the string functions, we make it possible to set directly during the forge.
- ip_sum: is the packet header checksum. It will be computed by default.
- ip_tos: is the “type of service” field. 0 by default
- ip_ttl: is the “Time To Live”. 64 by default.
- ip_v is: the IP version. 4 by default.

## RETURN VALUE

The IP datagram or NULL on error.

## ERRORS

- No valid dst_addr could be determined via call to **[plug_get_host_ip(3)](plug_get_host_ip.md)**

## EXAMPLES

**1** Forge the forged ip packet for later fill it with IGMP paget:
```cpp
ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_IGMP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);


igmp2 = forge_igmp_packet(ip    : ip_packet,
                          type  : 0x11,
                          code  : 0x00,
                          group : 0.0.0.0,
                          data  : "haha",
                          update_ip_len : FALSE);

```

## SEE ALSO

**[dump_ip_packet(3)](dump_ip_packet.md)**, **[dump_tcp_packet(3)](dump_tcp_packet.md)**, **[dump_udp_packet(3)](dump_udp_packet.md)**, **[dump_icmp_packet(3)](dump_icmp_packet.md)**, **[forge_icmp_packet(3)](forge_icmp_packet.md)**, **[forge_igmp_packet(3)](forge_igmp_packet.md)**, **[forge_ip_packet(3)](forge_ip_packet.md)**, **[forge_tcp_packet(3)](forge_tcp_packet.md)**, **[forge_udp_packet(3)](forge_udp_packet.md)**, **[get_icmp_element(3)](get_icmp_element.md)**, **[get_ip_element(3)](get_ip_element.md)**, **[get_tcp_element(3)](get_tcp_element.md)**, **[get_udp_element(3)](get_udp_element.md)**, **[insert_ip_options(3)](insert_ip_options.md)**, **[pcap_next(3)](pcap_next.md)**, **[set_ip_elements(3)](set_ip_elements.md)**, **[set_tcp_elements(3)](set_tcp_elements.md)**, **[insert_tcp_options(3)](insert_tcp_options.md)**, **[get_tcp_options(3)](get_tcp_options.md)**, **[set_udp_elements(3)](set_udp_elements.md)**, **[send_packet(3)](send_packet.md)**, **[forge_ipv6_packet(3)](forge_ipv6_packet.md)**, **[get_ipv6_element(3)](get_ipv6_element.md)**, **[set_ipv6_elements(3)](set_ipv6_elements.md)**, **[dump_ipv6_packet(3)](dump_ipv6_packet.md)**, **[insert_ipv6_options(3)](insert_ipv6_options.md)**, **[forge_tcp_v6_packet(3)](forge_tcp_v6_packet.md)**, **[get_tcp_v6_element(3)](get_tcp_v6_element.md)**, **[set_tcp_v6_elements(3)](set_tcp_v6_elements.md)**, **[insert_tcp_v6_options(3)](insert_tcp_v6_options.md)**, **[get_tcp_v6_options(3)](get_tcp_v6_options.md)**, **[dump_tcp_v6_packet(3)](dump_tcp_v6_packet.md)**, **[tcp_v6_ping(3)](tcp_v6_ping.md)**, **[forge_udp_v6_packet(3)](forge_udp_v6_packet.md)**, **[get_udp_v6_element(3)](get_udp_v6_element.md)**, **[set_udp_v6_elements(3)](set_udp_v6_elements.md)**, **[dump_udp_v6_packet(3)](dump_udp_v6_packet.md)**, **[forge_icmp_v6_packet(3)](forge_icmp_v6_packet.md)**, **[get_icmp_v6_element(3)](get_icmp_v6_element.md)**, **[dump_icmp_v6_packet(3)](dump_icmp_v6_packet.md)**, **[forge_igmp_v6_packet(3)](forge_igmp_v6_packet.md)**, **[send_v6packet(3)](send_v6packet.md)**, **[send_capture (3)](send_capture .md)**, **[get_local_mac_address_from_ip(3)](get_local_mac_address_from_ip.md)**, **[send_arp_request(3)](send_arp_request.md)**, **[forge_frame(3)](forge_frame.md)**, **[send_frame(3)](send_frame.md)**, **[dump_frame(3)](dump_frame.md)**
