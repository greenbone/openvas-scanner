# get_icmp_element

## NAME

**get_icmp_element** - Get an ICMP element from a IP datagram.

## SYNOPSIS

*int* **get_icmp_element**(icmp: *string*, element: *string*);

**get_icmp_element** It takes two named.


## DESCRIPTION

Get an ICMP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:

- icmp: is the IP datagram (not the ICMP part only).
- element: is the name of the field to get
  
Valid ICMP elements to get are:

- icmp_id
- icmp_code
- icmp_type
- icmp_seq
- icmp_chsum
- icmp_data


## RETURN VALUE

Returns an ICMP element from a IP datagram.

## ERRORS

- Missing *icmp* parameter.
- Missing *element* parameter.
- Element is not a valid element to get.

## EXAMPLES

**1** Dump the forged udp packet:
```cpp
data = "some data";

UDP_LEN = strlen(blat) + 8;
ip = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_UDP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);

udpip = get_icmp_element(ip : ip,
                         uh_sport : 32000,
                         uh_dport : 5060,
                         uh_ulen : UDP_LEN,
                         data : data);

dump_udp_packet (udpip);
```

## SEE ALSO

**[forge_ip_packet(3)](forge_ip_packet.md)**, **[dump_udp_packet(3)](dump_udp_packet.md)**
