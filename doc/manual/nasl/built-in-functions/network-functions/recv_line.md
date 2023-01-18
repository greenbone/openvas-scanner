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

**[close(3)](close.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[display(3)](../string-functions/display.md)**
