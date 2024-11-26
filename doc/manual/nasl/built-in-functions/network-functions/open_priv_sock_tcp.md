# open_priv_sock_tcp

## NAME

**open_priv_sock_tcp** - opens a “privileged” TCP socket to the target host.

## SYNOPSIS

*any* **open_priv_sock_tcp**(dport: *int*, sport: *int*, timeout: *int*);

**open_priv_sock_tcp** takes three named integer arguments:
- dport is the destination port
- sport is the source port, which may be inferior to 1024. This argument is optional.
  If it is not set, the function will try to open a socket on any port from 1 to 1023.
- timeout: An integer with the timeout value in seconds.  The default timeout is controlled by a global value.

## DESCRIPTION

Open a “privileged” TCP socket to the target host.

## RETURN VALUE

Return a socket, NULL on error.

## ERRORS

- Missing or undefined parameter dport
- Get socket option error

## EXAMPLES

**1**: Open and close a socket 
```cpp
soc = open_priv_sock_tcp(dport: 443, sport: 1000);
close(soc);

```

## SEE ALSO

**[close(3)](close.md)**
