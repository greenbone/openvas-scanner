# forge_tcp_packet

## NAME

**forge_tcp_packet** - Fills an IP datagram with TCP data.

## SYNOPSIS

*string* **forge_tcp_packet**(data: *string*, ip: *string*, th_ack: *int*, th_dport: *int*, th_flags: *TCP_HEADER_FLAG*, th_off: *int*, th_seq: *int*, th_sport: *int*, th_sum: *int*, th_urp: *int*, th_win: *int*, th_x2: *int*, update_ip_len: *int*);

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

- You must supply the *ip* argument: You get this error if you don't provide the named argument *ip*.


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

**[forge_ip_packet(3)](forge_ip_packet.md)**, **[dump_tcp_packet(3)](dump_tcp_packet.md)**
