# insert_tcp_v6_options

## NAME

**insert_tcp_v6_options** - insert TCP options to an IPv6 datagram

## SYNOPSIS

*string* **insert_tcp_v6_options**(tcp: *string*, *int*...);

**insert_tcp_v6_options** takes 1 named and any number of positional arguments

## DESCRIPTION

This function adds TCP options to a IPv6 datagram. The options are given as key value(s) pair with the positional argument list. The first positional argument is the identifier of the option, the next positional argument is the value for the option. For the option TCPOPT_TIMESTAMP (8) two values must be given.

Available options are:

- 2: TCPOPT_MAXSEG, values between 536 and 65535
- 3: TCPOPT_WINDOW, with values between 0 and 14
- 4: TCPOPT_SACK_PERMITTED, no value required.
- 8: TCPOPT_TIMESTAMP, 8 bytes value for timestamp and echo timestamp, 4 bytes each one.

## RETURN VALUE

The modified datagram

## EXAMPLES

**1**: insert a single option:

```c#
ip_packet = forge_ip_v6_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_IGMP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);

ip_packet = insert_tcp_v6_options(tcp: ip_packet, 2, 1234);
```

**2**: insert a multiple options with TCPOPT_TIMESTAMP:

```c#
ip_packet = forge_ip_v6_packet(ip_v : 4,
                     ip_hl : 5,
                     ip_tos : 0,
                     ip_len : 20,
                     ip_id : 0xFEAF,
                     ip_p : IPPROTO_IGMP,
                     ip_ttl : 255,
                     ip_off : 0,
                     ip_src : 192.168.0.1,
                     ip_dst : 192.168.0.12);

# The first value modifies the option TCPOPT_MAXSEG and has 1 value: 1234
# The second value modifies the option TCPOPT_TIMESTAMP and has 2 values: 20 and 25
ip_packet = insert_tcp_v6_options(tcp: ip_packet, 2, 1234, 8, 20, 25);
```

## SEE ALSO

**[forge_ip_v6_packet(3)](forge_ip_v6_packet.md)**
