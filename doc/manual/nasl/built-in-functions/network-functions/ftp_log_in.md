# ftp_log_in

## NAME

**ftp_log_in** - performs a FTP identification / authentication on an open socket

## SYNOPSIS

*any* **ftp_log_in**(user: *string*, pass: *string*, socket: *int*);

**ftp_log_in** takes three named arguments:
- user: is the user name (it has no default value like “anonymous” or “ftp”)
- pass: is the password (again, no default value like the user e-mail address)
- socket: an open socket.

## DESCRIPTION

Performs a FTP identification / authentication on an open socket.

## RETURN VALUE

Returns TRUE if it could login successfully, FALSE otherwise (e.g. wrong password, or any network problem).

## ERRORS
- Invalid socket value
 
## EXAMPLES

**1**: Performs an ftp login.
```cpp
soc = open_sock_tcp(23);
ftp_log_in(socket: soc, user: "foo", pass: "bar");
```

## SEE ALSO

**[open_sock_tcp(3)](open_sock_tcp.md)**
