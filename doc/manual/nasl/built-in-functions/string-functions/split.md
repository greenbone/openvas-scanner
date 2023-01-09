# split

## NAME

**split** - split a string into parts

## SYNOPSIS

*array* **split**(0: *string*, sep: *string*, keep: *bool*);

**split** takes 1 positional and up to 2 named arguments.

## DESCRIPTION

This function splits a given string into parts, puts them into an array and returns it.

The first positional argument is the *string* to split.

The optional named argument *sep* is a *string* containing the separator for splitting the string. The string is split after the separator. By default the string is split at every line break.

The optional named argument *keep* is a  *bool* and is used as flag to enable/disable keeping the separator within the separated string. By default *keep* is set to *TRUE*. *TRUE* means the separator is kept, *FALSE* means the separator is discarded.

## RETURN VALUE

The split string as an *array*

## EXAMPLES

1. Split string with keeping separator:
```c#
a = split("aabaabaa", sep: "b");

display(a);
# Displays [ 0: 'aab', 1: 'aab', 2: 'aa' ]
```

2. Split string discarding separator:
```c#
a = split("aabaabaa", sep: "b", keep: FALSE);

display(a);
# Displays [ 0: 'aa', 1: 'aa', 2: 'aa' ]
```