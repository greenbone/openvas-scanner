# resolve_host_name

## NAME

**resolve_host_name** - get an IP address corresponding to the host name

## SYNOPSIS

*string* **resolve_host_name**(hostname: *string*);

**resolve_host_name** takes one named argument

## DESCRIPTION

Tries to resolve the IP of a given hostname as IPv6.

The named parameter *hostname* is a *string* containing the hostname to resolve.

## RETURN VALUE

The resolve IPv6 as *string* or *NULL*, when the hostname could not be resolved or on an error

## ERRORS

The named parameter *hostname* is missing
