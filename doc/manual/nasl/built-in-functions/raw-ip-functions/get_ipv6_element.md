# get_ipv6_element

## NAME

**get_ipv6_element** - extracts a field from a IPv6 datagram.

## SYNOPSIS

*int* **get_ipv6_element**(ip6: *string*, element: *string*);

**get_ipv6_element** It takes two named parameters.


## DESCRIPTION

Same as **[get_ip_v6_element(3)](get_ip_v6_element.md)**.

Get an ICMP element from a IPv6 datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:

- ip: is the IPv6 datagram.
- element: is the name of the field to get
  
Valid IP elements to get are:

- ip6_v
- ip6_tc
- ip6_fl
- ip6_plen
- ip6_nxt
- ip6_hlim
- ip6_src
- ip6_dst

For more information of these fields look into **[forge_ip_v6_packet(3)](forge_ip_v6_packet.md)**.

## RETURN VALUE

Returns an IP element from a IPv6 datagram.

## ERRORS

- no valid 'ip' argument
- no valid 'element' argument
- unknown element

## SEE ALSO

**[forge_ip_v6_packet(3)](forge_ip_v6_packet.md)**
