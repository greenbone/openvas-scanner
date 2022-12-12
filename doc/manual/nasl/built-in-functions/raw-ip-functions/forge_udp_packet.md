# forge_udp_packet

## NAME

**forge_udp_packet** - Fills an IP datagram with UDP data.

## SYNOPSIS

*string* **forge_udp_packet**(data: *string*, ip: *string*, uh_dport: *int*, uh_sport: *int*, uh_sum: *int*, uh_ulen: *int*, update_ip_len: *int*);

**forge_udp_packet** It takes many named arguments, someones are optional. For details, see the description below.


## DESCRIPTION

Fills an IP datagram with UDP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:

- data: is the payload.
- ip: is the IP datagram to be filled.
- uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
- uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
- uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
- uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
- update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.
  

## RETURN VALUE

The modified IP datagram or NULL on error.

## ERRORS

- You must supply the *ip6* argument: You get this error if you don't provide the named argument *ip*.


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

udpip = forge_udp_packet(ip : ip,
                         uh_sport : 32000,
                         uh_dport : 5060,
                         uh_ulen : UDP_LEN,
                         data : data);

dump_udp_packet (udpip);
```

## SEE ALSO

**[forge_ip_packet(3)](forge_ip_packet.md)**, **[dump_udp_packet(3)](dump_udp_packet.md)**
