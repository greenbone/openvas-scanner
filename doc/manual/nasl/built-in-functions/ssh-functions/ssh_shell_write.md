# ssh_shell_write

## NAME

**ssh_shell_write** - write to a SSH shell

## SYNOPSIS

*int* **ssh_shell_write**(0: *int*, cmd: *string*);

**ssh_shell_write** takes one positional and one named argument.

## DESCRIPTION

This function write to an already opened SSH shell. Before using an SSH connection has to be established and a shell has to be opened with **[ssh_shell_open(3)](ssh_shell_open.md)** before.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

Be aware that the given session ID by **[ssh_shell_open(3)](ssh_shell_open.md)** is not used here!

The named argument *cmd* is given as string. It is written into the shell. The result of the command can be extracted by **[ssh_shell_read(3)](ssh_shell_read.md)**.

## RETURN VALUE

0 on success, -1 on error

## ERRORS

Invalid SSH session ID

Channel/shell session ID not found for SSH session

Argument *cmd* is missing or empty

Unable to write to the shell

## SEE ALSO

**[ssh_shell_open(3)](ssh_shell_open.md)**, **[ssh_shell_read(3)](ssh_shell_read.md)**, **[ssh_connect(3)](ssh_connect.md)**