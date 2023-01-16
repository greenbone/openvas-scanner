# leave_multicast_group

## NAME

**leave_multicast_group** - leaves a multicast group.

## SYNOPSIS

*any* **leave_multicast_group**(*string*);

**leave_multicast_group** takes a single unnamed argument, an IP multicast address.

## DESCRIPTION

Leaves a multicast group. Note that if *join_multicast_group* was called several times, each call to *leave_multicast_cast* only decrements a counter; the group is left when the counter reaches 0.


## RETURN VALUE

Return FAKE_CELL, or NULL on error

## ERRORS
- Invalid parameter
- Missing parameter
- Never join to the group

## EXAMPLES

**1**: Leave a multicast group
```cpp
join_multicast_group("224.0.0.1");
join_multicast_group("224.0.0.1");
leave_multicast_group("224.0.0.1");
leave_multicast_group("224.0.0.1");
```

## SEE ALSO

**[close(3)](close.md)**, **[end_denial(3)](end_denial.md)**, **[ftp_get_pasv_port(3)](ftp_get_pasv_port.md)**, **[get_host_name(3)](get_host_name.md)**, **[get_host_ip(3)](get_host_ip.md)**, **[get_host_open_port(3)](get_host_open_port.md)**, **[get_port_transport(3)](get_port_transport.md)**, **[get_port_state(3)](get_port_state.md)**, **[get_source_port(3)](get_source_port.md)**, **[get_tcp_port_state(3)](get_tcp_port_state.md)**, **[get_udp_port_state(3)](get_udp_port_state.md)**, **[islocalhost(3)](islocalhost.md)**, **[islocalnet(3)](islocalnet.md)**, **[join_multicast_group(3)](join_multicast_group.md)**, **[leave_multicast_group(3)](leave_multicast_group.md)**, **[open_priv_sock_tcp(3)](open_priv_sock_tcp.md)**, **[open_priv_sock_udp(3)](open_priv_sock_udp.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[open_sock_udp(3)](open_sock_udp.md)**, **[recv(3)](recv.md)**, **[recv_line(3)](recv_line.md)**, **[send(3)](send.md)**, **[scanner_add_port(3)](scanner_add_port.md)**, **[scanner_get_port(3)](scanner_get_port.md)**, **[tcp_ping(3)](tcp_ping.md)**, **[telnet_init(3)](telnet_init.md)**, **[this_host(3)](this_host.md)**, **[this_host_name(3)](this_host_name.md)**, **[ftp_log_in(3)](ftp_log_in.md)**, **[start_denial(3)](start_denial.md)**
