# Network Functions

## General

In case of error, all those functions returns a value that can be interpreted as FALSE (most of the time NULL).

## TABLE OF CONTENT

- **[close](close.md)** - closes the given socket.
- **[end_denial](end_denial.md)** - end denial
- **[ftp_get_pasv_port](ftp_get_pasv_port.md)** - sends the “PASV” command on the open socket, parses the returned data and returns the chosen “passive” port
- **[ftp_log_in](ftp_log_in.md)** - performs a FTP identification / authentication on an open socket
- **[get_host_ip](get_host_ip.md)** - get the IP of the currently scanned host
- **[get_host_name](get_host_name.md)** - get_host_names the given socket
- **[get_host_open_port](get_host_open_port.md)** - get an open TCP port on the target host
- **[get_mtu](get_mtu.md)** - get the maximum transition unit for the scanned host
- **[get_port_state](get_port_state.md)** - get a port state
- **[get_port_transport](get_port_transport.md)** - Get the encapsulation used for the given port, if it was previously stored in the kb.
- **[get_source_port](get_source_port.md)** - get port of a opened socket
- **[get_tcp_port_state](get_tcp_port_state.md)** - Get a port state
- **[get_udp_port_state](get_udp_port_state.md)** - get a udp port state.
- **[islocalhost](islocalhost.md)** - Check if the  target host is the same as the attacking host
- **[islocalnet](islocalnet.md)** - Check if the target host is on the same network as the attacking host
- **[join_multicast_group](join_multicast_group.md)** - join a multicast group.
- **[leave_multicast_group](leave_multicast_group.md)** - leaves a multicast group.
- **[open_priv_sock_tcp](open_priv_sock_tcp.md)** - opens a “privileged” TCP socket to the target host.
- **[open_priv_sock_udp](open_priv_sock_udp.md)** - opens a “privileged” UDP socket to the target host.
- **[open_sock_tcp](open_sock_tcp.md)** - opens a TCP socket to the target host.
- **[open_sock_udp](open_sock_udp.md)** - opens a UDP socket to the target host.
- **[recv_line](recv_line.md)** - receives data from a TCP or UDP socket.
- **[recv](recv.md)** - receives data from a TCP or UDP socket.
- **[scanner_add_port](scanner_add_port.md)** - declares an open port to openvas-scanner.
- **[scanner_get_port](scanner_get_port.md)** - walks through the list of open ports
- **[send](send.md)** - sends data on a socket
- **[start_denial](start_denial.md)** - initializes some internal data structure for end_denial
- **[tcp_ping](tcp_ping.md)** - launches a “TCP ping” against the target host
- **[telnet_init](telnet_init.md)** - performs a telnet negotiation on an open socket
- **[this_host](this_host.md)** - get the IP address of the current (attacking) machine
- **[this_host_name](this_host_name.md)** - get the host name of the current (attacking) machine
