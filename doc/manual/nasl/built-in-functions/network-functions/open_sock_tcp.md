# open_sock_tcp

## NAME

**open_sock_tcp** - opens a TCP socket to the target host.

## SYNOPSIS

*any* **open_sock_tcp**(*int*, bufsz: *int*, timeout: *int*, transport: *ENCPAPS*, priority: *string*);

**open_sock_tcp** takes an unnamed integer argument (the port number) and four optional named arguments:
- bufsz: An integer with the the size buffer size.  Note that by default, no buffering is used.
- timeout: An integer with the timeout value in seconds.  The default timeout is controlled by a global value.
- transport: One of the ENCAPS_* constants to force a specific encapsulation mode or force trying of all modes (ENCAPS_AUTO). This is for example useful to select a specific TLS or SSL version or use specific TLS connection setup priorities.  See *get_port_transport for a description of the ENCAPS constants.
- priority A string value with priorities for an TLS encapsulation. For the syntax of the priority string see the GNUTLS manual. This argument is only used in ENCAPS_TLScustom encapsulation.

## DESCRIPTION

Open a TCP socket to the target host.
This function is used to create a TCP connection to the target host.  It requires the port number as its argument and has various optional named arguments to control encapsulation, timeout and buffering.

## RETURN VALUE
A positive integer as a NASL socket, 0 on connection error or NULL on other errors.

## ERRORS


## EXAMPLES

**1**: Open and close a socket 
```cpp
ftpPort= 21;

# Specifying the defaults plus ARCFOUR-128:
prior = "NORMAL:+ARCFOUR-128"

soc = open_sock_tcp(ftpPort, transport:get_port_transport(ftpPort), priority: prior);
close(soc);
```

## SEE ALSO

**[close(3)](close.md)**, **[end_denial(3)](end_denial.md)**, **[ftp_get_pasv_port(3)](ftp_get_pasv_port.md)**, **[get_host_name(3)](get_host_name.md)**, **[get_host_ip(3)](get_host_ip.md)**, **[get_host_open_port(3)](get_host_open_port.md)**, **[get_port_transport(3)](get_port_transport.md)**, **[get_port_state(3)](get_port_state.md)**, **[get_source_port(3)](get_source_port.md)**, **[get_tcp_port_state(3)](get_tcp_port_state.md)**, **[get_udp_port_state(3)](get_udp_port_state.md)**, **[islocalhost(3)](islocalhost.md)**, **[islocalnet(3)](islocalnet.md)**, **[join_multicast_group(3)](join_multicast_group.md)**, **[leave_multicast_group(3)](leave_multicast_group.md)**, **[open_priv_sock_tcp(3)](open_priv_sock_tcp.md)**, **[open_priv_sock_udp(3)](open_priv_sock_udp.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[open_sock_udp(3)](open_sock_udp.md)**, **[recv(3)](recv.md)**, **[recv_line(3)](recv_line.md)**, **[send(3)](send.md)**, **[scanner_add_port(3)](scanner_add_port.md)**, **[scanner_get_port(3)](scanner_get_port.md)**, **[tcp_ping(3)](tcp_ping.md)**, **[telnet_init(3)](telnet_init.md)**, **[this_host(3)](this_host.md)**, **[this_host_name(3)](this_host_name.md)**, **[ftp_log_in(3)](ftp_log_in.md)**, **[start_denial(3)](start_denial.md)**
