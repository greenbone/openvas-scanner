# Raw IP Functions

## GENERAL

All those functions work on blocks of data which are implemented as “pure strings". This means that you could change them with the string manipulation functions, but this is probably not very easy.

## TABLE OF CONTENT

**dump_ip_packet** - dumps IP datagrams.
**dump_tcp_packet** - dumps the TCP parts of datagrams.
**dump_udp_packet** - dumps the UDP parts of datagrams.
**dump_icmp_packet** - dumps the ICMP parts of datagrams.
**forge_icmp_packet** - fills an IP datagram with ICMP data.
**forge_igmp_packet** - fills an IP datagram with IGMP data.
**forge_ip_packet** - returns an IP datagram inside the block of data.
**forge_tcp_packet** - fills an IP datagram with TCP data.
**forge_udp_packet** - fills an IP datagram with UDP data.
**get_icmp_element** - returns an ICMP element from a IP datagram.
**get_ip_element** - extracts a field from a datagram.
**get_tcp_element** - returns a TCP element from a IP datagram.
**get_udp_element** - returns an UDP element from a IP datagram.
**insert_ip_options** - adds an IP option to the datagram and returns the modified datagram.
**pcap_next** - listens to one packet and returns it.
**set_ip_elements** - modifies the fields of a datagram.
**set_tcp_elements** - modifies the TCP fields of a datagram.
**insert_tcp_options** - (since v21.04) Insert TCP options between add the end of the TCP header and before the data.
**get_tcp_options** - (since v21.04) get a single TCP options from a TCP header if the options is present.
**set_udp_elements** - modifies the UDP fields of a datagram.
**send_packet** - sends a list of packets (passed as unnamed arguments) and listens to the answers.
**forge_ipv6_packet** - Forge IPv6 packet.
**get_ipv6_element** - Obtain IPv6 header element.
**set_ipv6_elements** - Set IPv6 header element.
**dump_ipv6_packet** - Print IPv6 packet.
**insert_ipv6_options** - adds an IPv6 option to the datagram and returns the modified datagram.
**forge_tcp_v6_packet** - fills an IP datagram with TCP data. It returns the modified IPv6 datagram.
**get_tcp_v6_element** - Get TCP Header element.
**set_tcp_v6_elements** - Set TCP Header element.
**insert_tcp_v6_options** - (since v21.04) Insert TCP options between the end of the TCP header and before the data.
**get_tcp_v6_options** - (since v21.04) get a single TCP options from a TCP header if the options is present.
**dump_tcp_v6_packet** - Print TCP part of an IPv6 packet.
**tcp_v6_ping** - Performs TCP Connect to test if host is alive.
**forge_udp_v6_packet** - Forge v6 packet for UDP.
**get_udp_v6_element** - Get UDP Header element.
**set_udp_v6_elements** - Set UDP Header element.
**dump_udp_v6_packet** - Print UDP part of IPv6 packets.
**forge_icmp_v6_packet** - Forge ICMPv6 packet.
**get_icmp_v6_element** - Obtain ICMPv6 header element.
**dump_icmp_v6_packet** - Dumps the ICMP parts of datagrams.
**forge_igmp_v6_packet** - Forge IGMPv6 packet.
**send_v6packet** - Send forged IPv6 Packet.
**send_capture ** - Send a capture
**get_local_mac_address_from_ip** - Get the local mac addres given the IP.
**send_arp_request** - Sends the ARP request to the target's IP.
**forge_frame** - Forge a datalink layer frame.
**send_frame** - Sends a datalink frame through a raw socket.
**dump_frame** - Dump a frame. It is en hexadecimal representation.
