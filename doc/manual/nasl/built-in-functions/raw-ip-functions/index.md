# Raw IP Functions

## GENERAL

All those functions work on blocks of data which are implemented as “pure strings". This means that you could change them with the string manipulation functions, but this is probably not very easy.

## TABLE OF CONTENT

- **[dump_frame](dump_frame.md)** - print a datalink layer frame
- **[dump_icmp_packet](dump_icmp_packet.md)** - prints ICMP IPv4 packets
- **[dump_icmp_v6_packet](dump_icmp_v6_packet.md)** - prints the ICMP part of IPv6 datagrams
- **[dump_ip_packet](dump_ip_packet.md)** - dumps IP datagrams.
- **[dump_ip_v6_packet](dump_ip_v6_packet.md)** - print IPv6 header
- **[dump_ipv6_packet](dump_ipv6_packet.md)** - print IPv6 header
- **[dump_tcp_packet](dump_tcp_packet.md)** - print the TCP part of IPv4 datagrams
- **[dump_tcp_v6_packet](dump_tcp_v6_packet.md)** - print the tcp part of IPv6 datagrams
- **[dump_udp_packet](dump_udp_packet.md)** - print the UDP part of IPv4 datagrams
- **[dump_udp_v6_packet](dump_udp_v6_packet.md)** - print the UDP part of IPv6 datagrams
- **[forge_frame](forge_frame.md)** - forge a datalink layer frame
- **[forge_icmp_packet](forge_icmp_packet.md)** - fills an IP datagram with ICMP data.
- **[forge_icmp_v6_packet](forge_icmp_v6_packet.md)** - fills an IPv6 datagram with ICMP data.
- **[forge_igmp_packet](forge_igmp_packet.md)** - fills an IP datagram with IGMP data.
- **[forge_igmp_v6_packet](forge_igmp_v6_packet.md)** - fills an IPv6 datagram with IGMP data.
- **[forge_ip_packet](forge_ip_packet.md)** - Forge an IP datagram inside the block of data
- **[forge_ip_v6_packet](forge_ip_v6_packet.md)** - forge an IPv6 datagram inside the block of data
- **[forge_ipv6_packet](forge_ipv6_packet.md)** - Forge an IPv6 datagram inside the block of data, same as *forge_ip_v6_packet*
- **[forge_tcp_packet](forge_tcp_packet.md)** - Fills an IP datagram with TCP data.
- **[forge_tcp_v6_packet](forge_tcp_v6_packet.md)** - Fills an IPv6 datagram with TCP data.
- **[forge_udp_packet](forge_udp_packet.md)** - Fills an IP datagram with UDP data.
- **[forge_udp_v6_packet](forge_udp_v6_packet.md)** - Fills an IPv6 datagram with UDP data.
- **[get_icmp_element](get_icmp_element.md)** - Get an ICMP element from a IP datagram.
- **[get_icmp_v6_element](get_icmp_v6_element.md)** - Get an ICMP element from a IPv6 datagram.
- **[get_ip_element](get_ip_element.md)** - extracts a field from a IP datagram.
- **[get_ip_v6_element](get_ip_v6_element.md)** - extracts a field from a IPv6 datagram.
- **[get_ipv6_element](get_ipv6_element.md)** - extracts a field from a IPv6 datagram.
- **[get_local_mac_address_from_ip](get_local_mac_address_from_ip.md)** - get the MAC address of host
- **[get_tcp_element](get_tcp_element.md)** - extract TCP field from an IP datagram
- **[get_tcp_option](get_tcp_option.md)** - get a TCP option from an IP datagram if present
- **[get_tcp_v6_element](get_tcp_v6_element.md)** - extract TCP field from an IPv6 datagram
- **[get_tcp_v6_option](get_tcp_v6_option.md)** - get a TCP option from an IPv6 datagram if present
- **[get_udp_element](get_udp_element.md)** - extract UDP field from an IP datagram
- **[get_udp_v6_element](get_udp_v6_element.md)** - extract UDP field from an IPv6 datagram
- **[insert_ip_options](insert_ip_options.md)** - Add a option to a IP datagram
- **[insert_ip_v6_options](insert_ip_v6_options.md)** - Add a option to a IPv6 datagram
- **[insert_ipv6_options](insert_ipv6_options.md)** - Add a option to a IPv6 datagram
- **[insert_tcp_options](insert_tcp_options.md)** - insert TCP options to an IP datagram
- **[insert_tcp_v6_options](insert_tcp_v6_options.md)** - insert TCP options to an IPv6 datagram
- **[pcap_next](pcap_next.md)** - read the next packet
- **[send_arp_request](send_arp_request.md)** - send an arp request to the scanned host
- **[send_capture](send_capture.md)** - read the next packet
- **[send_frame](send_frame.md)** - send a frame to th  scanned host
- **[send_packet](send_packet.md)** - send a list of IP packets to the scanned host
- **[send_v6packet](send_v6packet.md)** - send a list of IPv6 packets to the scanned host
- **[set_ip_elements](set_ip_elements.md)** - modify the field of a IP datagram
- **[set_ip_v6_elements](set_ip_v6_elements.md)** - modify the field of a IPv6 datagram
- **[set_ipv6_elements](set_ipv6_elements.md)** - modify the field of a IPv6 datagram
- **[set_tcp_elements](set_tcp_elements.md)** - modify the TCP fields of an IP datagram
- **[set_tcp_v6_elements](set_tcp_v6_elements.md)** - modify the TCP fields of an IPv6 datagram
- **[set_udp_elements](set_udp_elements.md)** - modify the UDP fields of an IP datagram
- **[set_udp_v6_elements](set_udp_v6_elements.md)** - modify the UDP fields of an IPv6 datagram
- **[tcp_ping](tcp_ping.md)** - Launches a TCP ping against the target host
- **[tcp_v6_ping](tcp_v6_ping.md)** - Launches a TCP ping against the target host
