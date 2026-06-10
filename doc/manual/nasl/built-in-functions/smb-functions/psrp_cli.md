# psrp_cli

## NAME

**prsp_cli** - execute a command on a windows machine

## SYNOPSIS

*string* **prsp_cli**(interpreter: *string*, cmd:*string*, host:*string*, port:*int*, ssl:*bool* , path:*string*, authentication:*string*, username:*string*, password:*string*, additional_args: *nasl list*;

**win_cmd_exec** takes three named arguments.

## DESCRIPTION

This function runs a command on a target windows machine. As this function just works with pipes, it is not necessary to have a SMB or WMI implementation.

All arguments are mandatory, except for `additional_args`. `realm` and `kdc` are mandatory only for *Kerberos* authentication method.

## RETURN VALUE
 Nasl Array. The first element is the exit code, being 0 for success, 1 for error comming from the binary and 2 an error from the nasl function. The second element is the output of the command (response or error).

## ERRORS

One of the arguments are missing or empty.

All other error are specified on occurrences, as there can be many reasons, when using pipes.
