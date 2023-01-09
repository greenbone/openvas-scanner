# strstr

## NAME

**strstr** - finds the first occurrence of a sub-string within a string

## SYNOPSIS

*string* **strstr**(0: *string*, 1: *string*);

**strstr** takes two positional arguments

## DESCRIPTION

This function finds the first occurrence of a sub-string within a string.

The first positional argument is the *string* to search through.

The second positional argument is a *string* containing the sub-string to be searched for.
This function will return a sub-string of the original. If just the position is needed **[stridx(3)](stridx.md)** can be used instead.

## RETURN VALUE

A sub-string of the original string, beginning at the first occurrence of the found sub-string or *NULL* if none where found.

## SEE ALSO

**[stridx(3)](stridx.md)**