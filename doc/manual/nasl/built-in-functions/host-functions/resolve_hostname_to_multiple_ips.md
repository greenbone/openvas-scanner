# resolve_hostname_to_multiple_ips

## NAME

**resolve_hostname_to_multiple_ips** - resolve a hostname to all found addresses

## SYNOPSIS

*array* **resolve_hostname_to_multiple_ips**(hostname: *string*);

**resolve_hostname_to_multiple_ips** takes one named argument

## DESCRIPTION

This function creates a list of addresses a given host resolves to.

The named argument *hostname* is a *string* containing the hostname to resolve.

## RETURN VALUE

A *array* containing all found addresses or *NULL* on error.

## ERROR

The named parameter *hostname* is missing

## NOTE

Even if no address could be found, an empty NASL array is returned. A NASL array is always resolved to TRUE value even though it is empty.
