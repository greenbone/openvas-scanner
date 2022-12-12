# forge_icmp_v6_packet

## NAME

**forge_icmp_v6_packet** - fills an IPv6 datagram with ICMP data.

## SYNOPSIS

*string* **forge_icmp_v6_packet**(ip6: *string*, data: *string*, icmp_type: *int*, icmp_code: *int*, icmp_id: *int*, icmp_seq: *int*, reachable_time: *int*, retransmit_timer: *int*, flags: *int*, target: *string*, update_ip_len: *int*, icmp_cksum: *int*);

**forge_icmp_v6_packet** It takes up to 10 named arguments.


## DESCRIPTION
Fills an IPv6 datagram with ICMP data. Note that the ip_p field is not updated. It returns the modified IPv6 datagram. Its arguments are:
- *ip6*: IPv6 datagram that is updated.
- *data*: Payload.
- *icmp_type*: ICMP type. 0 by default.
- *icmp_code*: ICMP code. 0 by default.
- *icmp_id*: ICMP ID. 0 by default.
- *icmp_seq*: ICMP sequence number.
- *reachable_time*: Configures the duration that a router considers a remote IPv6 node reachable. 0 by default.
- *transmit_timer*: Configures the retransmit interval. The retransmit interval is the time between Link-State Advertisement (LSA) retransmissions to adjacent routers for a given interface. 0 by default.
- *update_ip_len*: If this flag is set, NASL will recompute the size field of the IP datagram. Default: True.
- *icmp_cksum*: Checksum, computed by default.

## RETURN VALUE

The modified IP datagram or NULL on error.

## ERRORS

- missing 'ip' parameter.
