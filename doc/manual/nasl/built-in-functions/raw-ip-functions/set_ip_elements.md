# set_ip_elements

## NAME

**set_ip_elements** - modify the field of a IP datagram

## SYNOPSIS

*string* **set_ip_elements**(ip: *string*, ip_hl: *int*, ip_id: *int*, ip_len: *int*, ip_off: *int*, ip_p: *int*, ip_src: *string*, ip_sum: *int*, ip_tos: *int*, ip_ttl: *int*, ip_v: *int*);

**set_ip_elements** takes up to 11 named arguments.


## DESCRIPTION

Set element from a IP datagram. Its arguments are:

- ip: IP datagram to set fields on
- ip_hl: IP header length in 32 bits words, 5 by default
- ip_id: datagram ID, random by default
- ip_len: length of the datagram, 20 plus the length of the data
- ip_off: fragment offset in 64 bits words, 0 by default
- ip_p: IP protocol, 0 by default
- ip_src: source address in ASCII, NASL will convert it into an integer in network order
- ip_sum: packet header checksum, it will be computed by default
- ip_tos: type of service field, 0 by default
- ip_ttl: time to live field, 64 by default
- ip_v: IP version, 4 by default

## RETURN VALUE

Returns the modified IP datagram
