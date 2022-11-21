# error_message

## NAME

**error_message** - Reports an error information.

## SYNOPSIS

*void* **error_message**(data: *string*, port:*int* , proto: *string*, uri: *string*);

**error_message** The error_message takes the following arguments:
- *data* is the text report (the “description” by default).
- port is the TCP or UDP port number of the service (or nothing if the bug concerns the whole machine, e.g. the IP stack configuration).
- proto (or protocol) is the protocol ("tcp" by default; "udp" is the other value).
- uri specifies the location of a found product (as port is only used by services, and for products is normally General/TCP)


## DESCRIPTION

This function reports an error information.


## RETURN VALUE

This function returns nothing.


## SEE ALSO

**[security_message(3)](security_message.md)**, **[log_message(3)](log_message.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
