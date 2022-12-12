# forge_ip_v6_packet

## NAME

**forge_ip_v6_packet** - forge an IPv6 datagram inside the block of data

## SYNOPSIS

*string* **forge_ip_v6_packet**(data: *string*, ip6_v: *int*, ip6_tc: *int*, ip6_fl: *int*, ip6_p: *int*, ip6_hlim: *int*, ip6_src: *string*, ip6_dst: *string*);

**forge_ip_v6_packet** It takes named arguments.


## DESCRIPTION
Forge an IPv6 datagram inside the block of data. It takes following arguments:

- data: is the payload.
- ip6_v: version, 6 by default.
- ip6_tc: Traffic class. 0 by default.
- ip6_fl: Flow label. 0 by default.
- ip_p: is the IP protocol. 0 by default.
- ip6_hlim: Hop limit. Max. 255. 64 by default.
- ip6_src: is the source address in ASCII. NASL will convert it into an integer in network order.
- ip6_dst: is the destination address in ASCII. NASL will convert it into an integer in network order. By default it takes the target IP address via call to **[plug_get_host_ip(3)](plug_get_host_ip.md)**. This option looks dangerous, but since anybody can edit an IP packet with the string functions, we make it possible to set directly during the forge.

## RETURN VALUE

The IP datagram or NULL on error.
