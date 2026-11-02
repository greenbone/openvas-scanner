# close(3nasl)

## NAME

**close** - closes the given socket.

## SYNOPSIS

*void* **close**(*FD*);

**close** takes single unnamed argument, the socket file descriptor to be close.

## DESCRIPTION

Closes the given socket.

## RETURN VALUE

Return FAKE_CELL, or Null on error

## ERRORS

- Invalid socket value

## EXAMPLES

Open and close a socket
```cpp
soc = open_sock_tcp(port);
close(soc);
```

## SEE ALSO

**[open_sock_tcp(3nasl)](open_sock_tcp.md)**
