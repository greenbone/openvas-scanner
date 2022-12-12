# forge_icmp_packet

## NAME

**forge_icmp_packet** - fills an IP datagram with ICMP data.

## SYNOPSIS

*string* **forge_icmp_packet**(icmp_code: *int*, icmp_type: *ICMP_MS_SYNC_REQ_TYPE*, icmp_seq: *int*, icmp_id: *ICMP_ID*, icmp_cksum: *int*, ip: *string*);

**forge_icmp_packet** It takes 


## DESCRIPTION
Fills an IP datagram with ICMP data. Note that the ip_p field is not updated. It returns the modified IP datagram. Its arguments are:
- *ip*: IP datagram that is updated.
- *data*: Payload.
- *icmp_cksum*: Checksum, computed by default.
- *icmp_code*: ICMP code. 0 by default.
- *icmp_id*: ICMP ID. 0 by default.
- *icmp_seq*: ICMP sequence number.
- *icmp_type*: ICMP type. 0 by default.
- *update_ip_len*: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.

## RETURN VALUE

The modified IP datagram or NULL on error.

## ERRORS

- missing 'ip' parameter.

## EXAMPLES

**1** Forge the forged icmp packet:
```cpp
ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_ICMP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);

icmp_packet = forge_icmp_packet(icmp_code:  0,
                                icmp_type:  ICMP_MS_SYNC_REQ_TYPE,
                                icmp_seq:   0,
                                icmp_id:    ICMP_ID,
                                icmp_cksum: -1,
                                ip:         ip_packet);

dump_icmp_packet (icmp_packet);
```

## SEE ALSO

**[forge_ip_packet(3)](forge_ip_packet.md)**, **[dump_icmp_packet(3)](dump_icmp_packet.md)**
