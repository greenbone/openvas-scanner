# dump_icmp_v6_packet

## NAME

**dump_icmp_v6_packet** - prints the ICMP part of IPv6 datagrams

## SYNOPSIS

*void* **dump_icmp_v6_packet**(*data*...);

**dump_icmp_v6_packet** takes any number of unnamed arguments.

## DESCRIPTION

Receive a list of IPv6 datagrams and print their ICMP part in a readable format in the screen.

A datagram can be created with **[forge_icmp_v6_packet(3)](forge_icmp_v6_packet.md)**.

## RETURN VALUE

None

## SEE ALSO

**[forge_icmp_packet(3)](forge_icmp_v6_packet.md)**
