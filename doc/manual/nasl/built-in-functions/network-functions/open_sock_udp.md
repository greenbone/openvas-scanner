# open_sock_udp

## NAME

**open_sock_udp** - opens a UDP socket to the target host.

## SYNOPSIS

*any* **open_sock_udp**(*int*);

**open_sock_udp** takes an unnamed integer argument (the port number)

## DESCRIPTION

Open a UDP socket to the target host.

## RETURN VALUE
A positive integer as a NASL socket, 0 on connection error or NULL on other errors.

## EXAMPLES

**1**: Open and close a socket 
```cpp
soc = open_sock_udp(5060);
close(soc);
```

## SEE ALSO

**[close(3)](close.md)**
