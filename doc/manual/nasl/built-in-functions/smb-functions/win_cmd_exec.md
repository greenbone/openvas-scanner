# win_cmd_exec

## NAME

**win_cmd_exec** - execute a command on a windows machine

## SYNOPSIS

*string* **win_cmd_exec**(username: *string*, password: *string*, cmd: *string*);

**win_cmd_exec** takes three named arguments.

## DESCRIPTION

This function runs a command on a target windows machine. As this function just works with pipes, it is not necessary to have a SMB or WMI implementation.

The named argument *username* is a *string* containing the user to run the command with.

The named argument *password* is a *string* containing the password for the user.

The named argument *cmd* is a *string* containing the command to execute.

## RETURN VALUE

The output of the run command as *string* or *NULL* on error.

## ERRORS

One of the arguments are missing or empty.

All other error are specified on occurrences, as there can be many reasons, when using pipes.
