# socket_get_ssl_session_id

## NAME

**socket_get_ssl_session_id** - takes an previously opened socket.

## SYNOPSIS

*str* **socket_get_ssl_session_id**(socket: int);

**socket_get_ssl_session_id** It takes one argument socket.

- socket - previously opened socket

## DESCRIPTION

Tries to get the TLS/SSL session id of an open socket.

## RETURN VALUE

Returns the used SSL/TLS version as string on success or NULL on failure.

## ERRORS

When either the given socket is not valid or when it was not possible to get the SSL/TLS version.

## EXAMPLES

```cpp
port = 22;
soc = open_sock_tcp( port );
if ( !soc )
  exit(1);
version = socket_get_ssl_session_id( socket:soc );
```

## SEE ALSO

**[open_sock_tcp](../network/open_sock_tcp.md)**, **[get_sock_info](get_sock_info.md)**
