# script_get_preference

## NAME

**script_get_preference** - get the value of a plugin preference

## SYNOPSIS

*string* **script_get_preference**(0: *string*);

**script_get_preference** takes 1 positional argument.

## DESCRIPTION

Get the value opf a plugin preference. Its argument is:
0. the name of the preference to get

## RETURN VALUE

The value of the preference or *NULL* on error

## ERRORS

- no argument was given
- the preference does not exist
