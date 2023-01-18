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

**[close(3)](close.md)**
