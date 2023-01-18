# send

## NAME

**send** - sends data on a socket

## SYNOPSIS

*any* **send**(socket: *soc*, data: *string*, length: *int*, option: *int*);

**send** takes the following named arguments:
- socket: the socket, of course.
- data: the data block. A string is expected here (pure or impure, this does not matter).
- length: is optional and will be the full data length if not set
- option: is the flags for the send() system call. You should not use a raw numeric value here.

## DESCRIPTION

Send data on a socket.

## RETURN VALUE

Return the amount of bytes sent on success. NULL on error.

## ERRORS

- Syntax error with the send() function with invalid socket or empty data.
 
## EXAMPLES

**1**: Open and send data on socket.
```cpp
data = "foo bar";
soc = open_sock_tcp(port);
n = send(socket:soc, data: data);

```

## SEE ALSO

**[open_sock_tcp(3)](open_sock_tcp.md)**
