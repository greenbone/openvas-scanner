# socket_check_ssl_safe_renegotiation

## NAME

**socket_check_ssl_safe_renegotiation** - check if secure renegotiation is supported in the server side

## SYNOPSIS

*int* **socket_check_ssl_safe_renegotiation**(socket: *int*);

**socket_check_ssl_safe_renegotiation** takes 1 named argument.

## DESCRIPTION

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

0 on success, <0 or *NULL* on failure.

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**
