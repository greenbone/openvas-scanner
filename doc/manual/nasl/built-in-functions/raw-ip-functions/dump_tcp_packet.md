# dump_tcp_packet

## NAME

**dump_tcp_packet** - print the TCP part of IPv4 datagrams

## SYNOPSIS

*NULL* **dump_tcp_packet**(*data*...);

**dump_tcp_packet** It takes any number of unnamed arguments.


## DESCRIPTION

Receive a list of IPv4 datagrams and print their TCP part in a readable format in the screen.

## RETURN VALUE

Return always NULL;

## EXAMPLES

**1** Dump the forged tcp packet:
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


tcp_packet = forge_tcp_packet(ip:       ip_packet,
                              th_sport: 5080,
                              th_dport: 80,
                              th_seq:   1000,
                              th_ack:   0,
                              th_x2:    0,
                              th_off:   5,
                              th_flags: TH_SYN,
                              th_win:   0,
                              th_sum:   0,
                              th_urp:   0);

dump_tcp_packet (ip_packet);
```
