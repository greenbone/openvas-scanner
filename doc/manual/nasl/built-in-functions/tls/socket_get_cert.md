# socket_get_cert

## NAME

**socket_get_cert** - takes an previously opened socket.

## SYNOPSIS

*str* **socket_get_cert**(socket: int);

**socket_get_cert** It takes one argument socket.

- socket - previously opened socket

## DESCRIPTION

Tries to get the certificate of an open socket.

## RETURN VALUE

Returns the a certificate as string on success or NULL on failure.

## ERRORS

When either the given socket is not valid or when it was not possible to get a certificate.

## EXAMPLES

```cpp
port = 22;
soc = open_sock_tcp( port );
if ( !soc )
  exit(1);
cert = socket_get_cert( socket:soc );
```

## SEE ALSO

**[open_sock_tcp](../network/open_sock_tcp.md)**, **[get_sock_info](get_sock_info.md)**
