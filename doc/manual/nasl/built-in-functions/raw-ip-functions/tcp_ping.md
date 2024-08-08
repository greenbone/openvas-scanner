# tcp_ping

## NAME

**tcp_ping** - launches a “TCP ping” against the target host

## SYNOPSIS

*any* **tcp_ping**(port: *int*);

**tcp_ping** takes single unnamed argument, the socket file descriptor to be tcp_ping.
- port: optional port to ping. Internal list of common ports is used as default.

## DESCRIPTION

Launches a “TCP ping” against the target host, i.e. tries to open a TCP connection and sees if anything comes back (SYNACK or RST). The named integer argument port is not compulsory: if it is not set, tcp_ping will use an internal list of common ports

## RETURN VALUE

Return 1 if Ping was successful, 0 else.
