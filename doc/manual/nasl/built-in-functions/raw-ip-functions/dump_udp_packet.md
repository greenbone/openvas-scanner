# dump_udp_packet

## NAME

**dump_udp_packet** - print the UDP part of IPv4 datagrams

## SYNOPSIS

*any* **dump_udp_packet**(*data*...);

**dump_udp_packet** It takes any number of unnamed arguments.


## DESCRIPTION

Receive a list of IPv4 datagrams and print their UDP part in a readable format in the screen.

## RETURN VALUE

Return always NULL;

## EXAMPLES

**1** Dump the forged udp packet:
```cpp
data = "some data";

UDP_LEN = strlen(blat) + 8;
ip = forge_ip_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_UDP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);

udpip = forge_udp_packet(ip : ip,
                         uh_sport : 32000,
                         uh_dport : 5060,
                         uh_ulen : UDP_LEN,
                         data : data);

dump_udp_packet (udpip);
```

## SEE ALSO

**[forge_ip_packet(3)](forge_ip_packet.md)**
