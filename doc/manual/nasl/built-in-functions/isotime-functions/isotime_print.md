# isotime_print

## NAME

**isotime_print** - convert ISO time string to a better readable form

*string* **isotime_print**(0: *string*);

**isotime_print** takes one positional argument.

## DESCRIPTION

Convert a standard isotime (`yyyymmddThhmmss`) into the human readable variant (`yyyy-mm-dd hh:mm:ss`).

The first unnamed argument is a *string* containing the string to convert.

## RETURN VALUE

The ISO time in a human readable form as *string* or *NULL* on error.

## ERRORS

First unnamed argument is either missing or in the wrong format.
