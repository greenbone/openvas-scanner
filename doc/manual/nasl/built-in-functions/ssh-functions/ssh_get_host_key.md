# ssh_get_host_key

## NAME

**ssh_get_host_key** - get the host key

## SYNOPSIS

*string* **ssh_get_host_key**(0: *int*);

**ssh_get_host_key** takes 1 positional argument

## DESCRIPTION

Get the MD5 host key.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

MD5 host key as *string* or *NULL* on invalid SSH session ID

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**