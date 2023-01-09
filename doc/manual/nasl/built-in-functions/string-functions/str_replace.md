# str_replace

## NAME

**str_replace** - replace a substring within a string

## SYNOPSIS

*string* **str_replace**(string: *string*, find: *string*, replace: *string*, count: *int*);

**str_replace** takes up to 4 named arguments.

## DESCRIPTION

This function looks up a substring within a string and replaces them with a given string.

The named argument *string* is a *string*. This string gets modified.

The named argument *find* is a *string*, containing the substring which is replaced.

The optional named argument *replace* is a *string*, containing the string which is inserted.

The optional named argument *count* is an *int*. It can limit the number of replacements. If for example set to 2, only the first two occurrences of the *find* string are replaced. Its default is 0, which means, all occurrences are replaced.

## RETURN VALUE

The new *string* with the sub-strings replaced or *NULL* on error.

## ERRORS

The argument *string* or *find* are missing.

## EXAMPLES

1. Replace a string:
```c#
a = str_replace(string: "abbcbbdbbe", find: "bb", replace: "xx");

display(a);
# Displays axxcxxdxxe
```