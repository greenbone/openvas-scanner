# ssh_request_exec

## NAME

**ssh_request_exec** - runs a command via SSH

## SYNOPSIS

*string* **ssh_request_exec**(0: *int*, cmd: *string*, stdout: *string*, stderr: *string*);

**ssh_request_exec** takes 1 positional and 3 named arguments

## DESCRIPTION

The function opens a channel to the remote end and ask it to execute a command.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

The command itself is expected as string in the named argument *cmd*.

The named parameter *stdout* and *stderr* are expected as *int* either set to 0 or 1. Regarding the handling of the stderr and stdout stream, this function may be used in different modes:
- if either the named arguments *stdout* or *stderr* are given and that one is set to 1, only the output of the specified stream is returned.
- if *stdout* and *stderr* are both given and set to 1, the output of both is returned interleaved.
NOTE: The following feature has not yet been implemented: The output is guaranteed not to switch between stderr and stdout within a line.
- if *stdout* and *stderr* are both given but set to 0, a special backward compatibility mode is used: First all output to stderr is collected up until any output to stdout is received. Then all output to stdout is returned while ignoring all further stderr output; at EOF the initial collected data from stderr is returned.
- if the named parameters *stdout* and *stderr* are not given, the function acts exactly as if only  *stdout* has been set to 1.

## RETURN VALUE

The output of the command as *string* or *NULL* on either invalid session ID or error

## ERRORS

The argument *cmd* is missing

Memory issues

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**