# security_message

## NAME

**security_message** - Reports a severe flaw.

## SYNOPSIS

*void* **security_message**(data: *string*, port:*int* , proto: *string*, uri: *string*);

**security_message** The security_message take following arguments:
- *data* is the text report (the “description” by default).
- port is the TCP or UDP port number of the service (or nothing if the bug concerns the whole machine, e.g. the IP stack configuration).
- proto (or protocol) is the protocol ("tcp" by default; "udp" is the other value).
- uri specifies the location of a found product (as port is only used by services, and for products is normally General/TCP)


## DESCRIPTION

This function will report a severe flaw.


## RETURN VALUE

This function returns nothing.


## SEE ALSO

**[log_message(3)](log_message.md)**, **[error_message(3)](error_message.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
