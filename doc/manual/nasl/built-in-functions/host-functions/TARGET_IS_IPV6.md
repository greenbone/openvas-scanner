# TARGET_IS_IPV6

## NAME

**TARGET_IS_IPV6** - check if the currently scanned target is an IPv6 address

## SYNOPSIS

*bool* **TARGET_IS_IPV6**();

**TARGET_IS_IPV6** takes no arguments

## DESCRIPTION

Check if the currently scanned target is an IPv6 address.

## RETURN VALUE

*TRUE* if the current target is an IPv6 address, else *FALSE*. In case of an error, *NULL* is returned.


## ERROR

No IP address for the current target is set.
