# tcp_ping

## NAME

**tcp_ping** - Launches a “TCP ping” against the target host.

## SYNOPSIS

*any* **tcp_ping**(port: *int*);

**tcp_ping** takes single unnamed argument, the socket file descriptor to be tcp_ping.
- port: optional port to ping. Internal list of common ports is used as default.

## DESCRIPTION

Launches a “TCP ping” against the target host, i.e. tries to open a TCP connection and sees if anything comes back (SYNACK or RST). The named integer argument port is not compulsory: if it is not set, tcp_ping will use an internal list of common ports

## RETURN VALUE

Return 1 if Ping was successful, 0 else.

## ERRORS

## EXAMPLES

**1**: Open and tcp_ping a socket 
```cpp
res = tcp_ping();

```

## SEE ALSO

**[close(3)](close.md)**, **[end_denial(3)](end_denial.md)**, **[ftp_get_pasv_port(3)](ftp_get_pasv_port.md)**, **[get_host_name(3)](get_host_name.md)**, **[get_host_ip(3)](get_host_ip.md)**, **[get_host_open_port(3)](get_host_open_port.md)**, **[get_port_transport(3)](get_port_transport.md)**, **[get_port_state(3)](get_port_state.md)**, **[get_source_port(3)](get_source_port.md)**, **[get_tcp_port_state(3)](get_tcp_port_state.md)**, **[get_udp_port_state(3)](get_udp_port_state.md)**, **[islocalhost(3)](islocalhost.md)**, **[islocalnet(3)](islocalnet.md)**, **[join_multicast_group(3)](join_multicast_group.md)**, **[leave_multicast_group(3)](leave_multicast_group.md)**, **[open_priv_sock_tcp(3)](open_priv_sock_tcp.md)**, **[open_priv_sock_udp(3)](open_priv_sock_udp.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[open_sock_udp(3)](open_sock_udp.md)**, **[recv(3)](recv.md)**, **[recv_line(3)](recv_line.md)**, **[send(3)](send.md)**, **[scanner_add_port(3)](scanner_add_port.md)**, **[scanner_get_port(3)](scanner_get_port.md)**, **[tcp_ping(3)](tcp_ping.md)**, **[telnet_init(3)](telnet_init.md)**, **[this_host(3)](this_host.md)**, **[this_host_name(3)](this_host_name.md)**, **[ftp_log_in(3)](ftp_log_in.md)**, **[start_denial(3)](start_denial.md)**
