# ssh_shell_close

## NAME

**ssh_shell_close** - close an SSH shell

## SYNOPSIS

*NULL* **ssh_shell_close**(0: *int*);

**ssh_shell_close** takes 1 positional argument

## DESCRIPTION

This function closes an opened SSH shell.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

The shell has to be opened with **[ssh_shell_open(3)](ssh_shell_open.md)** for the SSH session before.

## RETURN VALUE

*NULL*

## SEE ALSO

*[ssh_connect(3)](ssh_connect.md)**, **[ssh_shell_open(3)](ssh_shell_open.md)**