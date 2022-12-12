# set_ipv6_elements

## NAME

**set_ipv6_elements** - modify the field of a IPv6 datagram

## SYNOPSIS

*string* **set_ipv6_elements**(ip6: *string*, ip6_plen: *int*, ip6_hlim: *int*, ip6_nxt: *string*, ip6_src: *int*);

**set_ipv6_elements** takes up to 5 named arguments.


## DESCRIPTION

Set element from a IPv6 datagram. This function is the same as **[set_ip_v6_elements(3)](set_ip_v6_elements.md)**.

Its arguments are:
- ip6: IPv6 datagram to set fields on
- ip6_plen: payload length
- ip6_hlim: hop limit, max 255
- ip6_nxt: next packet
- ip6_src: source address

## RETURN VALUE

Returns the modified IPv6 datagram

## SEE ALSO

**[set_ip_v6_elements(3)](set_ip_v6_elements.md)**
