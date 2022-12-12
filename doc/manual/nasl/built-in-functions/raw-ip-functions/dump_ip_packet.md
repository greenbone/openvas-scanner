# dump_ip_packet

## NAME

**dump_ip_packet** - dumps IP datagrams.

## SYNOPSIS

*any* **dump_ip_packet**(*data*...);

**dump_ip_packet** takes any number of unnamed arguments.


## DESCRIPTION

Receive a list of IP packets and print them in a readable format in the screen.

## RETURN VALUE

None

## EXAMPLES

**1** :
```cpp
ip_packet = forge_ip_packet(ip_hl:  5,
                            ip_v:   4,
                            ip_tos: 0,
                            ip_id:  rand(),
                            ip_off: IP_DF,
                            ip_ttl: 64,
                            ip_p:   IPPROTO_TCP,
                            ip_sum: 0,
                            ip_src: 192.168.0.1,
                            ip_dst: 192.168.0.12);

dump_ip_packet (ip_packet);
```

## SEE ALSO

**[forge_ip_packet(3)](forge_ip_packet.md)**
