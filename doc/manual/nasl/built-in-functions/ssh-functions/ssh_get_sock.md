# ssh_get_sock

## NAME

**ssh_get_sock** - get the corresponding socket to a SSH session ID

## SYNOPSIS

*int* **ssh_get_sock**(0: *int*);

**ssh_get_sock** takes one positional argument.

## DESCRIPTION

The socket is either a native file descriptor or a NASL connection socket, if a open socket was passed to ssh_connect. The NASL network code handles both of them.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

An *int* representing the socket or or *NULL* on an invalid SSH session ID.

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**