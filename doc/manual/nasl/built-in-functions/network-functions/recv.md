# recv

## NAME

**recv** - receives data from a TCP or UDP socket.

## SYNOPSIS

*any* **recv**(socket: *int*, length: *int*, min: *int*, timeout: *int*);

**recv**  It takes at least two named arguments:

- socket which was returned by open_sock_tcp, for example
- length the number of bytes that you want to read at most. recv may return before length bytes have been read: as soon as at least one byte has been received, the timeout is lowered to 1 second. If no data is received during that time, the function returns the already read data; otherwise, if the full initial timeout has not been reached, a 1 second timeout is re-armed and the script tries to receive more data from the socket. This special feature was implemented to get a good compromise between reliability and speed when openvas-scanner talks to unknown or complex protocols. Two other optional named integer arguments can twist this behavior:
- min is the minimum number of data that must be read in case the “magic read function” is activated and the timeout is lowered. By default this is 0. It works together with length. More info https://lists.archive.carbon60.com/nessus/devel/13796
- timeout can be changed from the default.

## DESCRIPTION

Receives data from a TCP or UDP socket. For a UDP socket, if it cannot read data, NASL will suppose that the last sent datagram was lost and will sent it again a couple of time. 

## RETURN VALUE

String with the received data or NULL on error.

## EXAMPLES

**1**: Open a socket, recieve data, close the socket and finally display the data.
```cpp
soc = open_sock_tcp(port);
data = recv(socket: soc, length: 4096);
close(soc);
display(data);
```

## SEE ALSO

**[close(3)](close.md)**, **[open_sock_tcp(3)](open_sock_tcp.md)**, **[display(3)](../string-functions/display.md)**
