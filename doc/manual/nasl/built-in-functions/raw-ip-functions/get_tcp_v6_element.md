# get_tcp_v6_element

## NAME

**get_tcp_v6_element** - extract TCP field from an IPv6 datagram

## SYNOPSIS

*any* **get_tcp_v6_element**(tcp: *string*, element: *string*);

**get_tcp_v6_element** takes 2 named arguments.

## DESCRIPTION

Get an TCP element from a IPv6 datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:

- tcp: is the IP datagram.
- element: is the name of the field to get
  
Valid IP elements to get are:

- th_sport
- th_dsport
- th_seq
- th_ack
- th_x2
- th_off
- th_flags
- th_win
- th_sum
- th_urp
- data

For more information of these fields look into **[forge_tcp_v6_packet(3)](forge_tcp_v6_packet.md)**.

## RETURN VALUE

Returns an IP element from a IPv6 datagram.

## ERRORS

- no valid *tcp* argument
- no valid *element* argument
- unknown element

## SEE ALSO

**[forge_tcp_v6_packet(3)](forge_tcp_v6_packet.md)**
