# socket_get_error

## NAME

**socket_get_error** - takes the index of a previously created socket and returns an recorded error code.

## SYNOPSIS

*int* **socket_get_error**(int);

**socket_get_error** It takes one unnamed arguments.
- arg1 - must be valid index of a cached socket.

## DESCRIPTION

Returns a cached of error of an previously opened socket found via given index.

## RETURN VALUE

### NASL_ERR_NOERR;

No error.

### NASL_ERR_ETIMEDOUT;

Socket timed out.

### NASL_ERR_ECONNRESET;

Connection reset by peer.

### NASL_ERR_EUNREACH;

No route to host.

## ERRORS

When an invalid socket index is given it returns 0 which can be misleading.

## EXAMPLES

```cpp
port = 4242;
soc = open_sock_tcp(port);
if( !soc )
  exit(1);
errcode = socket_get_error( 0 );
```

## SEE ALSO

**[open_priv_sock_tcp](../network/open_priv_sock_tcp.md)**,  **[open_priv_sock_udp](../network/open_priv_sock_udp.md)**,  **[open_sock_tcp](../network/open_sock_tcp.md)**,  **[open_sock_udp](../network/open_sock_udp.md)**, **[socket_negotiate_ssl(3)](socket_negotiate_ssl.md)**
