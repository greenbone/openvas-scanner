# get_sock_info

## NAME

**get_sock_info** - takes an unnamed integer as socket, unnamed string as keyword and optinal asstring argument

## SYNOPSIS

*str* **get_sock_info**(int, string, bool);

**socket_get_ssl_version** It takes three arguments.

- unnamed integer as a socket,
- unnamed string that can be:
  -encaps: Return the encapsulation of the socket. Example output: ‘TLScustom‘.
  -tls-proto: Return a string with the actual TLS protocol in use. ‘n/a‘ is returned if no SSL/TLS session is active. Example output: ”TLSv1”.
  -tls-kx: Return a string describing the key exchange algorithm. Example output: ‘RSA‘.
  -tls-certtype: Return the type of the certificate in use by the session. Example output: ‘X.509‘
  -tls-cipher: Return the cipher algorithm in use by the session; Example output: ‘AES-256-CBC‘.
  -tls-mac: Return the message authentication algorithms used by the session. Example output: ‘SHA1‘.
  -tls-auth: Return the peer’s authentication type. Example ouput: ‘CERT‘.
  -tls-cert: Return the peer’s certificates for an SSL or TLS con nection. This is an array of binary strings or NULL if no certificate is known.
- asstring optional when encaps return human readable string

## DESCRIPTION

Retrieve various information about an active socket.
It requires the NASL socket number and a string to select the information to retrieve. 

Valid selection string arguments are:
-encaps: Return the encapsulation of the socket. Example output: ‘TLScustom‘.
-tls-proto: Return a string with the actual TLS protocol in use. ‘n/a‘ is returned if no SSL/TLS session is active. Example output: ”TLSv1”.
-tls-kx: Return a string describing the key exchange algorithm. Example output: ‘RSA‘.
-tls-certtype: Return the type of the certificate in use by the session. Example output: ‘X.509‘
-tls-cipher: Return the cipher algorithm in use by the session; Example output: ‘AES-256-CBC‘.
-tls-mac: Return the message authentication algorithms used by the session. Example output: ‘SHA1‘.
-tls-auth: Return the peer’s authentication type. Example ouput: ‘CERT‘.
-tls-cert: Return the peer’s certificates for an SSL or TLS con nection. This is an array of binary strings or NULL if no certificate is known.

## RETURN VALUE

Returns a string specified by the second argument.

## ERRORS

When either the given socket is not valid or when it was not possible to get the information.

## SEE ALSO

**[open_sock_tcp(3)](../network/open_sock_tcp.md)**
