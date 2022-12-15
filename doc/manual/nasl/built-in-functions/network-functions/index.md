# Network Functions

## General

In case of error, all those functions returns a value that can be interpreted as FALSE (most of the time NULL).

## TABLE OF CONTENT

**close** - closes the socket given in its only unnamed argument.
**end_denial** - takes no argument and returns TRUE if the target host is still alive and FALSE if it is dead. You must have called start_denial before your test.
**ftp_get_pasv_port** - sends the “PASV” command on the open socket, parses the returned data and returns the chosen “passive” port. It takes one named argument: socket.
**get_host_name** - takes no argument and returns the target host name. Forks for every vhost. Although it is internally based on forking execution of a script is NOT parallel.
**get_host_ip** - takes no arguments and returns the target IP address.
**get_host_open_port** - takes no argument and returns an open TCP port on the target host. This function is used by tests that need to speak to the TCP/IP stack but not to a specific service.
**get_port_transport** - takes an unnamed integer (socket) argument and returns its “encapsulation” (see page 23).
**get_port_state** - takes an unnamed integer (TCP port number) and returns TRUE if it is open and FALSE otherwise. As some TCP ports may be in an unknown state because they were not scanned, the behavior of this function may be modified by the “consider unscanned ports as closed” global option. When this option is reset (the default), get_port_state will return TRUE on unknown ports; when it is set, get_port_state will return FALSE.
**get_source_port** - takes an unnamed integer (opn TCP socket) and returns the source port (i.e. on the openvas-scanner host side).
**get_tcp_port_state** - is a synonym for get_port_state.
**get_udp_port_state** - returns TRUE if the UDP port is open, FALSE otherwise (see get_port_state for comments). Note that UDP port scanning may be unreliable.
**islocalhost** - takes no argument and returns TRUE if the target host is the same as the attacking host, FALSE otherwise.
**islocalnet** - takes no argument and returns TRUE if the target host is on the same network as the attacking host, FALSE otherwise.
**join_multicast_group** - takes an string argument (an IP multicast address) and returns TRUE if it could join the multicast group. If the group was already joined, the function joins increments an internal counter
**leave_multicast_group** - takes an string argument (an IP multicast address). Note that if join_multicast_group was called several times, each call to leave_multicast_cast only decrements a counter; the group is left when it reaches 0.
**open_priv_sock_tcp** - opens a “privileged” TCP socket to the target host.
**open_priv_sock_udp** - opens a “privileged” UDP socket to the target host.
**open_sock_tcp** - opens a TCP socket to the target host 22.
**open_sock_udp** - opens a UDP socket to the target host. It takes an unnamed integer argument, the port number.
**recv** - receives data from a TCP or UDP socket.
**recv_line** - receives data from socket and stops as soon as a line feed character has been read, length bytes have been read or the default timeout has been triggered.
**send** - sends data on a socket
**scanner_add_port** - declares an open port to openvas-scanner.
**scanner_get_port** - walks through the list of open ports. 
**tcp_ping** - launches a “TCP ping” against the target host.
**telnet_init** - performs a telnet negotiation on an open socket.
**this_host** - takes no argument and returns the IP address of the current (attacking) machine.
**this_host_name** - takes no argument and returns the host name of the current (attacking) machine.
**ftp_log_in** - performs a FTP identification / authentication on an open socket. 
**start_denial** - initializes some internal data structure for end_denial. It takes no argument and returns no value.
