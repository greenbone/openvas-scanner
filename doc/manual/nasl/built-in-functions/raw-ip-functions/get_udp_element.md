# get_udp_element

## NAME

**get_udp_element** - extract UDP field from an IP datagram

## SYNOPSIS

*any* **get_udp_element**(udp: *string*, element: *string*);

**get_udp_element** takes 2 named arguments.

## DESCRIPTION

Get an UDP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:

- udp: is the IP datagram.
- element: is the name of the field to get
  
Valid IP elements to get are:

- uh_sport
- uh_dport
- uh_ulen
- uh_sum
- data

For more information of these fields look into **[forge_udp_packet(3)](forge_udp_packet.md)**.

## RETURN VALUE

Returns an UDP element from a IP datagram.

## ERRORS

- no valid *udp* argument
- no valid *element* argument
- unknown element

## SEE ALSO

**[forge_udp_packet(3)](forge_udp_packet.md)**
