# isotime_is_valid

## NAME

**isotime_is_valid** - check if a ISO time string is valid

## SYNOPSIS

*bool* **isotime_is_valid**(0: *string*);

**isotime_is_valid** takes 1 positional argument.

## DESCRIPTION

Checks the validity for a given ISO time string. Valid strings are both the standard 15 byte string (`yyyymmddThhmmss`) and the better human readable up to 19 byte (`yyyy-mm-dd[ hh[:mm[:ss]]]`) are valid.

The first unnamed argument is the *string* to be checked.

## RETURN VALUE

A *bool* either TRUE or FALSE
