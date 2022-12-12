# get_tcp_v6_option

## NAME

**get_tcp_v6_option** - get a TCP option from an IPv6 datagram if present

## SYNOPSIS

*any* **get_tcp_v6_option**(tcp: *string*, option: *int*);

**get_tcp_v6_option** takes 2 named arguments.

## DESCRIPTION

Get a TCP option from a IPv6 datagram. Its arguments are:

- tcp: is the IP datagram.
- option: is the name of the field to get
  
Valid IP options to get are:

- 2: TCPOPT_MAXSEG, values between 536 and 65535
- 3: TCPOPT_WINDOW, with values between 0 and 14
- 4: TCPOPT_SACK_PERMITTED, no value required.
- 8: TCPOPT_TIMESTAMP, 8 bytes value for timestamp and echo timestamp, 4 bytes each one.

## RETURN VALUE

The returned option depends on the given *option* parameter. It is either an int for option 2, 3 and 4 or an array containing the two values for option 8.
