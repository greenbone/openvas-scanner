# add_host_name

## NAME

**add_host_name** - add a host name to the vhost list

## SYNOPSIS

*void* **add_host_name**(hostname: *string*, source: *string*);

**add_host_name** takes up to 2 named arguments

## DESCRIPTION

Expands the vHosts list with the given hostname.

The mandatory parameter *hostname* is of type *string*. It contains the hostname which should be added to the list of vHosts

Additionally a source, how the hostname was detected can be added with the named argument *source* as a *string*. If it is not given, the value *NASL* is set as default.

## RETURN VALUE

None

## ERRORS

The named argument *hostname* is missing.
