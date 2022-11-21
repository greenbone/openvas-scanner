# log_message

## NAME

**log_message** - Reports a miscellaneous information.

## SYNOPSIS

*void* **log_message**(data: *string*, port:*int* , proto: *string*, uri: *string*);

**log_message** The log_message takes the following arguments:
- *data* is the text report (the “description” by default).
- port is the TCP or UDP port number of the service (or nothing if the bug concerns the whole machine, e.g. the IP stack configuration).
- proto (or protocol) is the protocol ("tcp" by default; "udp" is the other value).
- uri specifies the location of a found product (as port is only used by services, and for products is normally General/TCP)


## DESCRIPTION

This function reports a miscellaneous information.


## RETURN VALUE

This function returns nothing.


## SEE ALSO

**[security_message(3)](security_message.md)**, **[error_message(3)](log_message.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
