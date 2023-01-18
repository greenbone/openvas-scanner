# script_get_preference_file_location

## NAME

**script_get_preference_file_location** - get the location of a plugin preference of type "file"

## SYNOPSIS

*string* **script_get_preference_file_location**(0: *string*);

**script_get_preference_file_location** takes 1 positional argument.

## DESCRIPTION

As files sent to the server (e.g. as plugin preference) are stored at pseudo-random locations with different names, the "real" file name has to be looked up in a hash table.

Its argument is:
0. name of the preference

## RETURN VALUE

Location of the preference or *NULL* on error.

## ERRORS

- no argument was given
- the preference is not of type file
