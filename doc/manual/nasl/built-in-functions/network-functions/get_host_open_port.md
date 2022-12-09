# get_host_open_port

## NAME

**get_host_open_port** - Get an open TCP port on the target host.

## SYNOPSIS

*any* **get_host_open_port**();

**get_host_open_port** takes no arguments.

## DESCRIPTION

This function is used by tests that need to speak to the TCP/IP stack but not to a specific service. 
Don't always return the first open port, otherwise it might get bitten by OSes doing active SYN flood countermeasures. Also, avoid returning 80 and 21 as open ports, as many transparent proxies are acting for these.

## RETURN VALUE

Return a random open port from a list (if there is many open ports), the port 21 or the port 80 are the last choices. Returns 0 if there is no open port.


## ERRORS

 
## EXAMPLES

**1**: Get and display an open port in the host target.
```cpp
port = get_host_open_port();
display(port);

```

## SEE ALSO

**[close(3)](close.md)**, **[end_denial(3)](end_denial.md)**, **[ftp_get_pasv_port(3)](ftp_get_pasv_port.md)**, **[get_host_name(3)](get_host_name.md)**, **[get_host_ip(3)](get_host_ip.md)**, **[get_host_open_port(3)](get_host_open_port.md)**, **[get_port_transport(3)](get_port_transport.md)**, **[get_port_state(3)](get_port_state.md)**, **[get_source_port(3)](get_source_port.md)**, **[get_tcp_port_state(3)](get_tcp_port_state.md)**, **[get_udp_port_state(3)](get_udp_port_state.md)**, **[islocalhost(3)](islocalhost.md)**, **[islocalnet(3)](islocalnet.md)**, **[join_multicast_group(3)](join_multicast_group.md)**, **[leave_multicast_group(3)](leave_multicast_group.md)**, **[open_priv_sock_tcp(3)](open_priv_sock_tcp.md)**, **[open_priv_sock_udp(3)](open_priv_sock_udp.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[open_sock_udp(3)](open_sock_udp.md)**, **[recv(3)](recv.md)**, **[recv_line(3)](recv_line.md)**, **[send(3)](send.md)**, **[scanner_add_port(3)](scanner_add_port.md)**, **[scanner_get_port(3)](scanner_get_port.md)**, **[tcp_ping(3)](tcp_ping.md)**, **[telnet_init(3)](telnet_init.md)**, **[this_host(3)](this_host.md)**, **[this_host_name(3)](this_host_name.md)**, **[ftp_log_in(3)](ftp_log_in.md)**, **[start_denial(3)](start_denial.md)**
