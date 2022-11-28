# pread

## NAME

**pread** - runs a command on the host system

## SYNOPSIS

*string* **pread**(cmd: *string*, argv: *array(string)*, cd: *Optional(boolean)*, drop_privileges_user: Optional(*string*));

**pread** takes 4 named arguments, of which 2 are optional.

## DESCRIPTION

This function is used to run a command on the host system. The output of the command is returned, can be saved and used for further processing.

It is also possible to change the working directory to the directory, in which the command was found.

In addition the user, who runs the command can be set.

This function will spawn a process on the host system.

*cmd* is a *string* parameter. It sets the name of the command to run. This can be either just the command, which will then be looked up in the path or a absolute path to a command.

*argv* is an *array* of strings. These are the parameter for the command call. Note that *argv\[0\]* is the name of the program, which can be different from *cmd*, but will be equal in most cases.

*cd* is an optional *boolean* parameter. By default it is set to *FALSE*. If it is set to *TRUE* the current directory is changed to the directory, where the command was found.

*drop_privileges_user* is an optional *string* parameter. When given, it sets the given user as the owner of the spawned process.

## RETURN VALUE

command output, *string*

## ERRORS

cannot spawn multiple processes per script, **pread** is not reentrant

unable to drop privileges for given user

parameter *cmd* is missing

parameter *argv* is missing

command *cmd* not found

unable to change directory

unable to read output


## EXAMPLES

**1**: Search for a command and run it
```cpp
if ( find_in_path("foo") ) {
    out = pread(cmd: "foo", argv: NULL, cd: FALSE, drop_privileges_user: NULL);
}
```

## SEE ALSO

**[find_in_path(3)](find_in_path.md)**