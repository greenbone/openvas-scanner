# ssh_get_issue_banner

## NAME

**ssh_get_issue_banner** - get the issue banner

## SYNOPSIS

*string* **ssh_get_issue_banner**(0: *int*);

**ssh_get_issue_banner** takes 1 positional argument.

## DESCRIPTION

The issue banner is normally displayed before a SSH authentication.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

The SSH issue banner as *string* or *NULL* on an invalid SSH session ID.

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**, **[ssh_server_banner(3)](ssh_get_server_banner.md)**