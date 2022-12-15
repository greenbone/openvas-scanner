# same_host

## NAME

**same_host** - compare two hosts

## SYNOPSIS

*bool* **same_host**(0: *string*, 1: *string*, cmp_hostname: *bool*);

**same_host** takes two unnamed arguments and one named argument

## DESCRIPTION

Compare if two hosts are the same.

The first two unnamed arguments are *string* containing the host to compare

If the named argument *cmp_hostname* is set to *TRUE*, the given hosts are resolved into their hostnames

## RETURN VALUE

TRUE if both hosts are the same, else FALSE. In case of an error a *NULL* is returned instead

## ERRORS

One of the two positional arguments are missing

One of the hostnames is too long, max length: 255
