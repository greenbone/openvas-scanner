# set_tcp_v6_elements

## NAME

**set_tcp_v6_elements** - modify the TCP fields of an IPv6 datagram

## SYNOPSIS

*string* **set_tcp_v6_elements**(tcp: *string*, data: *string*, th_ack: *int*, th_dport: *int*, th_flags: *int*, th_off: *int*, th_seq: *int*, th_sport: *int*, th_sum: *int*, th_urp: *int*, th_win: *int*, th_x2: *int*, update_ip_len: *int*);

**set_tcp_v6_elements** takes 13 named arguments.

## DESCRIPTION

This function modifies the TCP fields of an IPv6 datagram. Its arguments are:

- tcp: is the IPv6 datagram to be filled.
- data: is the TCP data payload.
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

The modified datagram
