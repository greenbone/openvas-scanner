# insert_ip_v6_options

## NAME

**insert_ip_v6_options** - Add a option to a IPv6 datagram

## SYNOPSIS

*string* **insert_ip_v6_options**(ip6: *string*, code: *int*, length: *int*, value: *string*);

**insert_ip_v6_options** takes 4 named arguments

## DESCRIPTION

Add a option to a specified IPv6 datagram. This function is the same as **[insert_ipv6_options(3)](insert_ipv6_options.md)**.

- ip: is the IP datagram
- code: is the identifier of the option to add
- length: is the length of the option data
- value: is the option data

## RETURN VALUE

A new IPv6 datagram with the given option set.

## SEE ALSO

**[insert_ipv6_options(3)](insert_ipv6_options.md)**
