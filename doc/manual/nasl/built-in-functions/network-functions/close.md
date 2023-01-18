# close

## NAME

**close** - closes the given socket.

## SYNOPSIS

*void* **close**(*FD*);

**close** takes single unnamed argument, the socket file descriptor to be close.

## DESCRIPTION



## RETURN VALUE

Return FAKE_CELL, or Null on error

## ERRORS

- Invalid socket value
 
## EXAMPLES

**1**: Open and close a socket 
```cpp
soc = open_sock_tcp(port);
close(soc);

```

## SEE ALSO

**[open_sock_tcp(3)](open_sock_tcp.md)**