# script_get_preference_file_content

## NAME

**script_get_preference_file_content** - get the file contents of a plugins preference that is of type "file"

## SYNOPSIS

*string* **script_get_preference_file_content**(0: *string*);

**script_get_preference_file_content** takes up to 2 named arguments

## DESCRIPTION

As files sent to the scanner (e.g. as plugin preference) are stored in a hash table with an identifier supplied by the client as the key, the contents have to be looked up.

Its argument is:
0. name of the preference

## RETURN VALUE

Content of the file or *NULL* on error

## ERRORS

- no argument was given
- the preference is not of type file
