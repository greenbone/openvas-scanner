# get_host_name_source

## NAME

**get_host_name_source** - get the hostname source

## SYNOPSIS

*string* **get_host_name_source**(hostname: *string*);

**get_host_name_source** takes one named argument

## DESCRIPTION

This function returns the source of detection of a given hostname.

The named parameter *hostname* is a *string* containing the hostname.

When no hostname is given, the current scanned host is taken.

If no virtual hosts are found yet this function always returns *IP-address*.

## RETURN VALUE

Source of detection of a given hostname as *string* or *NULL* if hostname unknown

## SEE ALSO

**[add_host_name(3)](add_host_name.md)**