# ssh_shell_read

## NAME

**ssh_shell_read** - read the output of a SSH shell

## SYNOPSIS

*string* **ssh_shell_read**(0: *int*, timeout: *int*);

**ssh_shell_read** takes 1 positional argument and up to 1 named argument.

## DESCRIPTION

This function read an output of an active SSH shell. Before being able to read, a SSH connection has to be established before and a shell has to be opened with **[ssh_shell_open(3)](ssh_shell_open.md)**.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

Be aware that the given session ID by **[ssh_shell_open(3)](ssh_shell_open.md)** is not used here!

The positional argument *timeout* is given as *int*. It sets the timeout for an blocking read. If not set the data is red non-blocking.

## RETURN VALUE

Data read from the shell as *string* or *NULL* in either an invalid session ID or error.

## ERRORS

Unable to read data.

## SEE ALSO

**[ssh_shell_open(3)](ssh_shell_open.md)**, **[ssh_shell_open(3)](ssh_shell_open.md)**