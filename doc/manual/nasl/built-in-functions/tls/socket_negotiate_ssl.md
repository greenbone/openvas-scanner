# socket_negotiate_ssl

## NAME

**socket_negotiate_ssl** - takes an previously opened socket and the transport type to negotiate an ssl/tls connection with it.

## SYNOPSIS

*int* **socket_negotiate_ssl**(socket: int, transport: int);

**socket_negotiate_ssl** It takes two arguments port and transport while transport is optional and will default to `ENCAPS_TLScustom` to allow outdated algorithm.

- socket - previously opened socket
- transport - an enum of transport possibilities.

Possible transport values are:
- `ENCAPS_AUTO` - tries to identify the transport protocol automatically
- `ENCAPS_SSLv23` - `NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-SSL3.0:+ARCFOUR-128:%COMPAT` 
- `ENCAPS_SSLv2` - `NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-SSL3.0:+ARCFOUR-128:%COMPAT` 
- `ENCAPS_SSLv3` - `NORMAL:-VERS-TLS-ALL:+VERS-SSL3.0:+ARCFOUR-128:%COMPAT`
- `ENCAPS_TLSv1` - `NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0:+ARCFOUR-128:%COMPAT`
- `ENCAPS_TLSv11` - `NORMAL:-VERS-TLS-ALL:+VERS-TLS1.1:+ARCFOUR-128:%COMPAT`
- `ENCAPS_TLSv12` - `NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:+ARCFOUR-128:%COMPAT`
- `ENCAPS_TLSv13` - `NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3:%COMPAT`
- `ENCAPS_TLScustom` - `NORMAL:+ARCFOUR-128:%COMPAT`
- `ENCAPS_MAX` - `NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-SSL3.0:+ARCFOUR-128:%COMPAT` 

## DESCRIPTION

Enriches given socket with TLS/SSL functionality when possible. It closes given socket when it is not possible to negotiate a TLS/SSL connection.

## RETURN VALUE

Returns the previously given socket index on success or NULL on failure.

## ERRORS

When either the given socket is not valid or when it was not possible to negotiate a TLS/SSL connection than it returns NULL.

## EXAMPLES

```cpp
port = 22;
soc = open_sock_tcp( port, transport:ENCAPS_IP );
if ( !soc )
  exit(1);
if( ! socket_negotiate_ssl( socket:soc ) )
  exit(1);
```

## SEE ALSO

**[open_sock_tcp](../network/open_sock_tcp.md)**
