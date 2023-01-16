# ftp_log_in

## NAME

**ftp_log_in** - performs a FTP identification / authentication on an open socket.

## SYNOPSIS

*any* **ftp_log_in**(user: *string*, pass: *string*, socket: *int*);

**ftp_log_in** takes three named arguments:
- user: is the user name (it has no default value like “anonymous” or “ftp”)
- pass: is the password (again, no default value like the user e-mail address)
- socket: an open socket.

## DESCRIPTION

Performs a FTP identification / authentication on an open socket.

## RETURN VALUE

Returns TRUE if it could login successfully, FALSE otherwise (e.g. wrong password, or any network problem).

## ERRORS
- Invalid socket value
 
## EXAMPLES

**1**: Performs an ftp login.
```cpp
soc = open_sock_tcp(23);
ftp_log_in(socket: soc, user: "foo", pass: "bar");
```

## SEE ALSO

**[close(3)](close.md)**, **[end_denial(3)](end_denial.md)**, **[ftp_get_pasv_port(3)](ftp_get_pasv_port.md)**, **[get_host_name(3)](get_host_name.md)**, **[get_host_ip(3)](get_host_ip.md)**, **[get_host_open_port(3)](get_host_open_port.md)**, **[get_port_transport(3)](get_port_transport.md)**, **[get_port_state(3)](get_port_state.md)**, **[get_source_port(3)](get_source_port.md)**, **[get_tcp_port_state(3)](get_tcp_port_state.md)**, **[get_udp_port_state(3)](get_udp_port_state.md)**, **[islocalhost(3)](islocalhost.md)**, **[islocalnet(3)](islocalnet.md)**, **[join_multicast_group(3)](join_multicast_group.md)**, **[leave_multicast_group(3)](leave_multicast_group.md)**, **[open_priv_sock_tcp(3)](open_priv_sock_tcp.md)**, **[open_priv_sock_udp(3)](open_priv_sock_udp.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[open_sock_udp(3)](open_sock_udp.md)**, **[recv(3)](recv.md)**, **[recv_line(3)](recv_line.md)**, **[send(3)](send.md)**, **[scanner_add_port(3)](scanner_add_port.md)**, **[scanner_get_port(3)](scanner_get_port.md)**, **[tcp_ping(3)](tcp_ping.md)**, **[telnet_init(3)](telnet_init.md)**, **[this_host(3)](this_host.md)**, **[this_host_name(3)](this_host_name.md)**, **[ftp_log_in(3)](ftp_log_in.md)**, **[start_denial(3)](start_denial.md)**
