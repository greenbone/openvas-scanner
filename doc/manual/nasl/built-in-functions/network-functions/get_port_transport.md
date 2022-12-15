# get_port_transport

## NAME

**get_port_transport** - Get the encapsulation used for the given port, if it was previously stored in the kb.

## SYNOPSIS

*any* **get_port_transport**(*int*, asstring: *bool*);

**get_port_transport** takes an unnamed argument, the port number, and a named parameter `asstring`. 

## DESCRIPTION

Get the encapsulation used for the given port.

Currently, there are the following encapsulation types:
- ENCAPS_AUTO = 0, Request auto detection.
- ENCAPS_IP = 1, this is the “transport” value for a pure TCP socket.
- ENCAPS_SSLv23 = 2, this is the “transport” value for a SSL connection in compatibility mode. Note that the find_service plugin will never declare a port with this "encapsulation", but you may use it in a script.
- ENCAPS_SSLv2 = 3, The old SSL version which only supports server side certificates. By the way, there is only one plugin that really tries to destroy data. This is http_methods.nasl
- ENCAPS_SSLv3 = 4, The new SSL version: it supports server and client side certificates, more ciphers, and fixes a few security holes.
- ENCAPS_TLSv1 = 5, TLSv1 is defined RFC 2246. Some people call it “SSL v3.1”.
- ENCAPS_TLSv11 = 6
- ENCAPS_TLSv12 = 7
- ENCAPS_TLSv13 = 8
- ENCAPS_TLScustom = 9, SSL/TLS using custom priorities.
- ENCAPS_MAX = 10

## RETURN VALUE

Return the transport encapsulation mode (OPENVAS_ENCAPS_*) for the given PORT.  If no such encapsulation mode has been stored in the knowledge base (or its value is < 0), OPENVAS_ENCAPS_IP is currently returned.
The return value depends on the parameters. An integer or a string with the encapsulation mode or NULL on error.

## ERRORS

 
## EXAMPLES

**1**: Get and display the encapsulation mode for the port
```cpp
encps = get_port_transport(443);
display(encps);
```

## SEE ALSO

**[close(3)](close.md)**, **[end_denial(3)](end_denial.md)**, **[ftp_get_pasv_port(3)](ftp_get_pasv_port.md)**, **[get_host_name(3)](get_host_name.md)**, **[get_host_ip(3)](get_host_ip.md)**, **[get_host_open_port(3)](get_host_open_port.md)**, **[get_port_transport(3)](get_port_transport.md)**, **[get_port_state(3)](get_port_state.md)**, **[get_source_port(3)](get_source_port.md)**, **[get_tcp_port_state(3)](get_tcp_port_state.md)**, **[get_udp_port_state(3)](get_udp_port_state.md)**, **[islocalhost(3)](islocalhost.md)**, **[islocalnet(3)](islocalnet.md)**, **[join_multicast_group(3)](join_multicast_group.md)**, **[leave_multicast_group(3)](leave_multicast_group.md)**, **[open_priv_sock_tcp(3)](open_priv_sock_tcp.md)**, **[open_priv_sock_udp(3)](open_priv_sock_udp.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[open_sock_udp(3)](open_sock_udp.md)**, **[recv(3)](recv.md)**, **[recv_line(3)](recv_line.md)**, **[send(3)](send.md)**, **[scanner_add_port(3)](scanner_add_port.md)**, **[scanner_get_port(3)](scanner_get_port.md)**, **[tcp_ping(3)](tcp_ping.md)**, **[telnet_init(3)](telnet_init.md)**, **[this_host(3)](this_host.md)**, **[this_host_name(3)](this_host_name.md)**, **[ftp_log_in(3)](ftp_log_in.md)**, **[start_denial(3)](start_denial.md)**
