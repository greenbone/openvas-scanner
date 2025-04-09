# script_get_preference

## NAME

**script_get_preference** - get the value of a plugin preference

## SYNOPSIS

*string* **script_get_preference**(id: *int*, 0: *string*);

**script_get_preference** takes 1 optional named argument and 1 optional positional argument.

## DESCRIPTION

Get the value of a plugin preference. Its arguments are:
id: the preference ID.
0. the name of the preference to get

At least one argument is required to get the preference. If both are given, the ID has priority.

## RETURN VALUE

The value of the preference or *NULL* on error

## ERRORS

- no argument was given
- the preference does not exist
