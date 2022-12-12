# forge_tcp_v6_packet

## NAME

**forge_tcp_v6_packet** - Fills an IPv6 datagram with TCP data.

## SYNOPSIS

*string* **forge_tcp_v6_packet**(ip6: *string*, data: *string*, th_sport: *int*, th_dport: *int*, th_ack: *int*, th_x2: *int*, th_off: *int*, th_flags: *int*, th_seq: *int*, th_win: *int*, th_sum: *int*, th_urp: *int*);

**forge_tcp_v6_packet** It takes many named arguments, someones are optionals. For details, seethe description below.


## DESCRIPTION

Fills an IPv6 datagram with TCP data. Note that the ip_p field is not updated. It returns the modified IPv6 datagram. Its arguments are:

- ip: is the IP datagram to be filled.
- data: is the TCP data payload.
- th_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
- th_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
- th_ack: is the acknowledge number. NASL will convert it into network order if necessary. 0 by default.
- th_x2: is a reserved field and should probably be left unchanged. 0 by default.
- th_off: is the size of the TCP header in 32 bits words. By default, 5.
- th_flags: are the TCP flags. 0 by default.
- th_seq: is the TCP sequence number. NASL will convert it into network order if necessary. Random by default.
- th_win: is the TCP window size. NASL will convert it into network order if necessary. 0 by default.
- th_sum: is the TCP checksum. By default, the right value is computed.
- th_urp: is the urgent pointer. 0 by default.


## RETURN VALUE

The modified IP datagram or NULL on error.

## ERRORS

- You must supply the *ip6* argument: You get this error if you don't provide the named argument *ip*.
