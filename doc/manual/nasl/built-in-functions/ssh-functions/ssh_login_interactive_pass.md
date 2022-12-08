# ssh_login_interactive_pass

## NAME

**ssh_login_interactive_pass** - finishes an authentication process

## SYNOPSIS

*int* **ssh_login_interactive_pass**(0: *int*, password: *string*);

**ssh_login_interactive_pass** takes 1 positional and up to one named argument

## DESCRIPTION

The function end an authentication process started by **[ssh_login_interactive(3)](ssh_login_interactive.md)**.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

The named argument *password* contains the password for authentication.

Alternatively an non-interactive authentication can be done with **[ssh_userauth(3)](ssh_userauth.md)**.

## RETURN VALUE

An *int* representing the status.
- 0 indicates a success
- -1 indicates a failure

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**, **[ssh_login_interactive(3)](ssh_login_interactive.md)**, **[ssh_userauth(3)](ssh_userauth.md)**