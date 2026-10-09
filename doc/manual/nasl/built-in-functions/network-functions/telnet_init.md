# telnet_init(3nasl)

## NAME

**telnet_init** - performs a telnet negotiation on an open socket

## SYNOPSIS

*any* **telnet_init**(*int*);

**telnet_init** This function takes one unnamed argument, the open socket.

## DESCRIPTION

Read the data on the socket (more or less the telnet dialog plus the banner).

## RETURN VALUE

Return FAKE_CELL, or Null on error

## ERRORS

- Invalid socket value
 
## EXAMPLES

**1**: Open a socket and print the telnet banner. 
```cpp
soc = open_sock_tcp(21);
banner = telnet_init(soc);
display(banner);
close(soc);
```

## SEE ALSO

**[close(3nasl)](close.md)**, **[open_sock_tcp(3nasl)](open_sock_tcp.md)**, **[display(3nasl)](../string-functions/display.md)**
