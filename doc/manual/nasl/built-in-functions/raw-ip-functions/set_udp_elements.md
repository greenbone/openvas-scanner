# set_udp_elements

## NAME

**set_udp_elements** - modify the UDP fields of an IP datagram

## SYNOPSIS

*string* **set_udp_elements**(udp: *string*, data: *string*, uh_dport: *int*, uh_sport: *int*, uh_sum: *int*, uh_ulen: *int*);

**set_udp_elements** takes 6 named arguments.

## DESCRIPTION

This function modifies the UDP fields of an IP datagram. Its arguments are:

- udp: is the IP datagram to be filled.
- data: is the payload.
- uh_dport: is the destination port. NASL will convert it into network order if necessary. 0 by default.
- uh_sport: is the source port. NASL will convert it into network order if necessary. 0 by default.
- uh_sum: is the UDP checksum. Although it is not compulsory, the right value is computed by default.
- uh_ulen: is the data length. By default it is set to the length the data argument plus the size of the UDP header.

## RETURN VALUE

The modified datagram
