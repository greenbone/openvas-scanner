# ip_reverse_lookup

## NAME

**ip_reverse_lookup** - gets the host name of either the given IP address or the current target

## SYNOPSIS

*string* **ip_reverse_lookup**( *string* );

Takes an optional *string* parameter, which is the IP address to look up. If no parameter is given, the IP address of the current target is used.

## DESCRIPTION

This function uses the `gethostbyaddr` function to get the host name of the given IP address. If no IP address is given, the IP address of the current target is used.

## RETURN VALUE

Return the found host name or NULL if the host name could not be retrieved. 
