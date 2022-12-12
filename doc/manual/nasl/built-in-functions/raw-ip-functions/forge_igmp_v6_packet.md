# forge_igmp_v6_packet

## NAME

**forge_igmp_v6_packet** - fills an IPv6 datagram with IGMP data.

## SYNOPSIS

*string* **forge_igmp_v6_packet**(ip6: *string*, data: *string*, code: *int*, group: *string*, type:  *int*, update_ip_len: *bool*);

**forge_igmp_v6_packet** It takes named arguments.


## DESCRIPTION
Fills an IPv6 datagram with IGMP data. Note that the ip_p field is not updated. It returns the modified IPv6 datagram. Its arguments are:
- ip6: IPv6 datagram that is updated.
- data: Payload.
- code: IGMP code. 0 by default.
- group: IGMP group
- type: IGMP type. 0 by default.
- update_ip_len: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.

## RETURN VALUE

The modified IP datagram or NULL on error.

## ERRORS

- missing 'ip' parameter.
