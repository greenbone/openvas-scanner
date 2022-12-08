# ssh_shell_open

## NAME

**ssh_shell_open** - requests an SSH shell

## SYNOPSIS

*int* **ssh_shell_open**(0: *int*, pty: *int*);

**ssh_shell_open** takes 1 positional and up to 1 named argument

## DESCRIPTION

Open an SSH shell. This shell can be either interactive or non-interactive. A session for the shell is created and saved for the SSH session.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

The optional named argument *pty* contains an *int*. If set to 1 the shell will become interactive, for all other values it will be non-interactive. The default is 1.

A opened shell has to be closed afterwards with **[ssh_shell_close](ssh_shell_close.md)**.

## RETURN VALUE

A session ID corresponding to the shell instance as *int* or *NULL* or either an invalid SSH session ID or error.

## ERRORS

Unable to open a channel

Unable to request a SSH shell

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**, **[ssh_shell_close](ssh_shell_close.md)**