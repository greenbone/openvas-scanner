# forge_udp_v6_packet

## NAME

**forge_udp_v6_packet** - Fills an IPv6 datagram with UDP data.

## SYNOPSIS

*string* **forge_udp_v6_packet**(ip6: *string*, data: *string*, uh_sport: *int*, uh_dport: *int*, uh_sum: *int*, uh_ulen: *int*, update_ip_len: *int*);

**forge_udp_v6_packet** It takes many named arguments, someones are optional. For details, see the description below.


## DESCRIPTION

Fills an IPv6 datagram with UDP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:

- ip6: is the IPv6 datagram to be filled.
- data: is the payload.
- uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
- uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
- uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
- uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.
- update_ip_len: is a flag (TRUE by default). If set, NASL will recompute the size field of the IP datagram.

## RETURN VALUE

The modified IP datagram or NULL on error.

## ERRORS

- You must supply the *ip6* argument: You get this error if you don't provide the named argument *ip*.
