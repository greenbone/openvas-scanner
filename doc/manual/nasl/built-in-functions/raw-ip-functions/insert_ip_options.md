# insert_ip_options

## NAME

**insert_ip_options** - Add a option to a IP datagram

## SYNOPSIS

*string* **insert_ip_options**(ip: *string*, code: *int*, length: *int*, value: *string*);

**insert_ip_options** takes 4 named arguments

## DESCRIPTION

Add a option to a specified IP datagram.

- ip: is the IP datagram
- code: is the identifier of the option to add
- length: is the length of the option data
- value: is the option data

## RETURN VALUE

A new IP datagram with the given option set.
