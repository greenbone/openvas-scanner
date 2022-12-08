# ssh_session_id_from_sock

## NAME

**ssh_session_id_from_sock** - get the SSH session ID from a socket

## SYNOPSIS

*int* **ssh_session_id_from_sock**(0: *int*);

**ssh_session_id_from_sock** takes one positional argument.

## DESCRIPTION

Given a socket, return the corresponding SSH session ID.

The first positional argument is a NASL socket value.

## RETURN VALUE

An *int* corresponding to an active SSH session ID or 0 if no session ID is known for the given socket.

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**