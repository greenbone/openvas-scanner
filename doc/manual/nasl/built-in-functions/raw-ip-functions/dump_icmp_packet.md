# dump_icmp_packet

## NAME

**dump_icmp_packet** - prints ICMP IPv4 packets

## SYNOPSIS

*void* **dump_icmp_packet**(*data*...);

**dump_icmp_packet** takes any number of unnamed arguments.

## DESCRIPTION

Receive a list of IPv4 ICMP packets and print them in a readable format in the screen.

A packet can be created with **[forge_icmp_packet(3)](forge_icmp_packet.md)**.

## RETURN VALUE

None

## EXAMPLES

**1** Dump the forged icmp packet:
```cpp
ip_packet = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_TCP,
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

**[forge_icmp_packet(3)](forge_icmp_packet.md)**, **[forge_ip_packet(3)](forge_ip_packet.md)**
