# scanner_get_port

## NAME

**scanner_get_port** - walks through the list of open ports

## SYNOPSIS

*any* **scanner_get_port**(*int*);

**scanner_get_port** takes a single unnamed argument, the index.

## DESCRIPTION

Walks through the list of open ports.
If the plugin is a port scanner, it needs to report the list of open ports back to openvas scanner, and it also needs to know which ports are to be scanned.


## RETURN VALUE
Returns a port number or 0 when the end of the list if reached.

## ERRORS
Index should be 0 the first time you call i
 
## EXAMPLES

**1**: Get the open port in position 3 in a list.
```cpp
port = scanner_get_port(3);
```

## SEE ALSO

**[close(3)](close.md)**, **[end_denial(3)](end_denial.md)**, **[ftp_get_pasv_port(3)](ftp_get_pasv_port.md)**, **[get_host_name(3)](get_host_name.md)**, **[get_host_ip(3)](get_host_ip.md)**, **[get_host_open_port(3)](get_host_open_port.md)**, **[get_port_transport(3)](get_port_transport.md)**, **[get_port_state(3)](get_port_state.md)**, **[get_source_port(3)](get_source_port.md)**, **[get_tcp_port_state(3)](get_tcp_port_state.md)**, **[get_udp_port_state(3)](get_udp_port_state.md)**, **[islocalhost(3)](islocalhost.md)**, **[islocalnet(3)](islocalnet.md)**, **[join_multicast_group(3)](join_multicast_group.md)**, **[leave_multicast_group(3)](leave_multicast_group.md)**, **[open_priv_sock_tcp(3)](open_priv_sock_tcp.md)**, **[open_priv_sock_udp(3)](open_priv_sock_udp.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[open_sock_udp(3)](open_sock_udp.md)**, **[recv(3)](recv.md)**, **[recv_line(3)](recv_line.md)**, **[send(3)](send.md)**, **[scanner_add_port(3)](scanner_add_port.md)**, **[scanner_get_port(3)](scanner_get_port.md)**, **[tcp_ping(3)](tcp_ping.md)**, **[telnet_init(3)](telnet_init.md)**, **[this_host(3)](this_host.md)**, **[this_host_name(3)](this_host_name.md)**, **[ftp_log_in(3)](ftp_log_in.md)**, **[start_denial(3)](start_denial.md)**
