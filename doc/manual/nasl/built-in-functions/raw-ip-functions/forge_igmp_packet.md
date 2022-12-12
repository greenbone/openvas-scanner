# forge_igmp_packet

## NAME

**forge_igmp_packet** - fills an IP datagram with IGMP data.

## SYNOPSIS

*string* **forge_igmp_packet**(ip: *string*, data: *string*, code: *int*, group: *string*, type:  *int*, update_ip_len: *bool*);

**forge_igmp_packet** It takes named arguments.


## DESCRIPTION
Fills an IP datagram with IGMP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
- ip: IP datagram that is updated.
- data: Payload.
- code: IGMP code. 0 by default.
- group: IGMP group
- type: IGMP type. 0 by default.
- update_ip_len: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.

## RETURN VALUE

The modified IP datagram or NULL on error.

## ERRORS

- missing 'ip' parameter.

## EXAMPLES

**1** Forge the forged igmp packet:
```cpp
ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_IGMP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);


igmp2 = forge_igmp_packet(ip    : ip_packet,
                          type  : 0x11,
                          code  : 0x00,
                          group : 0.0.0.0,
                          data  : "haha",
                          update_ip_len : FALSE);

```

## SEE ALSO

**[forge_ip_packet(3)](forge_ip_packet.md)**
