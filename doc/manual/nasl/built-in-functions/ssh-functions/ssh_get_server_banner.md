# ssh_get_server_banner

## NAME

**ssh_get_server_banner** - get the server banner

## SYNOPSIS

*string* **ssh_get_server_banner**(0: *int*);

**ssh_get_server_banner** takes one positional argument

## DESCRIPTION

This is usually the first data sent by the SSH server.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

The SSH server banner as *string* or *NULL* on an invalid SSH session ID.

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**, **[ssh_get_issue_banner(3)](ssh_get_issue_banner.md)**