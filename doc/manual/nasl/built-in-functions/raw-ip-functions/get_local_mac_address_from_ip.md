# get_local_mac_address_from_ip

## NAME

**get_local_mac_address_from_ip** - get the MAC address of host

## SYNOPSIS

*string* **get_local_mac_address_from_ip**(0: *string*);

**get_local_mac_address_from_ip** takes one unnamed argument.

## DESCRIPTION

Get the MAC address of a local IP address.

The first positional argument is a local IP address as *string*.

## RETURN VALUE

The resolved local MAC address corresponding to the given IP or *NULL* on error.

## ERRORS

 - Invalid IP
 - Not a local IP
 - IP does not resolve do a MAC
