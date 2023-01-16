# recv_line

## NAME

**recv_line** - receives data from a TCP or UDP socket.

## SYNOPSIS

*any* **recv_line**(socket: *int*, length: *int*, timeout: *int*);

**recv_line**  It takes at least two named arguments:

- socket: which was returned by open_sock_tcp, for example
- length: the number of bytes that you want to read at most.
- timeout: can be changed from the default. Default: no timeout

## DESCRIPTION

Receives data from a TCP or UDP socket and stops as soon as a line feed character has been read, length bytes have been read or the default timeout has been triggered. 

## RETURN VALUE
String with the received data or NULL on error.

## ERRORS
- missing or undefined parameter length or socket.

## EXAMPLES

**1**: Open a socket, recieve data, close the socket and finally display the data.
```cpp
soc = open_sock_tcp(port);
data = recv_line(socket: soc, length: 4096, timeout: 10);
close(soc);
display(data);
```

## SEE ALSO

**[close(3)](close.md)**, **[end_denial(3)](end_denial.md)**, **[ftp_get_pasv_port(3)](ftp_get_pasv_port.md)**, **[get_host_name(3)](get_host_name.md)**, **[get_host_ip(3)](get_host_ip.md)**, **[get_host_open_port(3)](get_host_open_port.md)**, **[get_port_transport(3)](get_port_transport.md)**, **[get_port_state(3)](get_port_state.md)**, **[get_source_port(3)](get_source_port.md)**, **[get_tcp_port_state(3)](get_tcp_port_state.md)**, **[get_udp_port_state(3)](get_udp_port_state.md)**, **[islocalhost(3)](islocalhost.md)**, **[islocalnet(3)](islocalnet.md)**, **[join_multicast_group(3)](join_multicast_group.md)**, **[leave_multicast_group(3)](leave_multicast_group.md)**, **[open_priv_sock_tcp(3)](open_priv_sock_tcp.md)**, **[open_priv_sock_udp(3)](open_priv_sock_udp.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[open_sock_udp(3)](open_sock_udp.md)**, **[recv(3)](recv.md)**, **[recv_line(3)](recv_line.md)**, **[send(3)](send.md)**, **[scanner_add_port(3)](scanner_add_port.md)**, **[scanner_get_port(3)](scanner_get_port.md)**, **[tcp_ping(3)](tcp_ping.md)**, **[telnet_init(3)](telnet_init.md)**, **[this_host(3)](this_host.md)**, **[this_host_name(3)](this_host_name.md)**, **[ftp_log_in(3)](ftp_log_in.md)**, **[start_denial(3)](start_denial.md)**
