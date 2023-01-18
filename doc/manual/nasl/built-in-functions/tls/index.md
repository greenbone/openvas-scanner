# TLS functions

## GENERAL

These functions are related to the handling of the sockets within a NASL script - for example the implementation of the NASL built-ins open_sock_tcp, send, recv, recv_line, and close.

## TABLE OF CONTENT

- **[get_sock_info](get_sock_info.md)** - takes an unnamed integer as socket, unnamed string as keyword and optinal asstring argument
- **[socket_cert_verify](socket_cert_verify.md)** - takes an previously opened socket.
- **[socket_check_ssl_safe_renegotiation](socket_check_ssl_safe_renegotiation.md)** - check if secure renegotiation is supported in the server side
- **[socket_get_cert](socket_get_cert.md)** - takes an previously opened socket.
- **[socket_get_error](socket_get_error.md)** - takes the index of a previously created socket and returns an recorded error code.
- **[socket_get_ssl_ciphersuite](socket_get_ssl_ciphersuite.md)** - takes an previously opened socket.
- **[socket_get_ssl_session_id](socket_get_ssl_session_id.md)** - takes an previously opened socket.
- **[socket_get_ssl_version](socket_get_ssl_version.md)** - takes an previously opened socket.
- **[socket_negotiate_ssl](socket_negotiate_ssl.md)** - takes an previously opened socket and the transport type to negotiate an ssl/tls connection with it.
- **[socket_ssl_do_handshake](socket_ssl_do_handshake.md)** - do a re-handshake of the TLS/SSL protocol
