# get_port_transport

## NAME

**get_port_transport** - Get the encapsulation used for the given port, if it was previously stored in the kb.

## SYNOPSIS

*any* **get_port_transport**(*int*, asstring: *bool*);

**get_port_transport** takes an unnamed argument, the port number, and a named parameter `asstring`. 

## DESCRIPTION

Get the encapsulation used for the given port.

Currently, there are the following encapsulation types:
- ENCAPS_AUTO = 0, Request auto detection.
- ENCAPS_IP = 1, this is the “transport” value for a pure TCP socket.
- ENCAPS_SSLv23 = 2, this is the “transport” value for a SSL connection in compatibility mode. Note that the find_service plugin will never declare a port with this "encapsulation", but you may use it in a script.
- ENCAPS_SSLv2 = 3, The old SSL version which only supports server side certificates. By the way, there is only one plugin that really tries to destroy data. This is http_methods.nasl
- ENCAPS_SSLv3 = 4, The new SSL version: it supports server and client side certificates, more ciphers, and fixes a few security holes.
- ENCAPS_TLSv1 = 5, TLSv1 is defined RFC 2246. Some people call it “SSL v3.1”.
- ENCAPS_TLSv11 = 6
- ENCAPS_TLSv12 = 7
- ENCAPS_TLSv13 = 8
- ENCAPS_TLScustom = 9, SSL/TLS using custom priorities.
- ENCAPS_MAX = 10

## RETURN VALUE

Return the transport encapsulation mode (OPENVAS_ENCAPS_*) for the given PORT.  If no such encapsulation mode has been stored in the knowledge base (or its value is < 0), OPENVAS_ENCAPS_IP is currently returned.
The return value depends on the parameters. An integer or a string with the encapsulation mode or NULL on error.
