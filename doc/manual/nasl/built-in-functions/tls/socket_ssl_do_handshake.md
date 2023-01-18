# socket_ssl_do_handshake

## NAME

**socket_ssl_do_handshake** - do a re-handshake of the TLS/SSL protocol

## SYNOPSIS

*int* **socket_ssl_do_handshake**(socket: *int*);

**socket_ssl_do_handshake** takes 1 named argument.

## DESCRIPTION

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

1 on success, 0 on NASL error or <0 on handshake error.

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**
