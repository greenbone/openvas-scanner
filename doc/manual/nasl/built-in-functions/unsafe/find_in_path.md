# find_in_path

## NAME

**find_in_path** - searches a command in $PATH and returns TRUE if found, or FALSE if not. It takes one string argument (the command name)

## SYNOPSIS

*boolean* **find_in_path**(0: *string*);

**find_in_path** takes 1 positional argument.


## DESCRIPTION

This function is used to check if a command exists in $PATH on the scanner host system. If the command exists, this function returns a *TRUE* value, if not it return a *FALSE* value.

The first positional argument is the command which is searched for.


## RETURN VALUE

*TRUE* if the command exists in $PATH, or *FALSE* if not


## EXAMPLES

**1**: Search for a command and run it
```cpp
if ( find_in_path("foo") ) {
    out = pread(cmd: "foo", argv: NULL, cd: FALSE, drop_privileges_user: NULL);
}
```

## SEE ALSO

**[pread(3)](pread.md)**