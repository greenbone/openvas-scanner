# crap

## NAME

**crap** - fill a string of desired length with given pattern

## SYNOPSIS

*string* **crap**(0: *int*, length: *int*, data: *string*);

**crap** takes up to 1 positional and 2 named arguments.

## DESCRIPTION

This function creates a buffer of the requested length and fills it with a repeated pattern. This function is mainly used for overflow tests.

The first positional and the named argument *length* are of type *int*, containing the desired length of the buffer. Only one of the both arguments can be set. If both are set, an error is thrown.

The named argument *data* is a *string* containing the pattern, which is repeated until the buffer is full. This argument is optional and *X* is the default value.

## RETURN VALUE

The buffer filled with the patter as *string* or *NULL* on error.

## ERRORS

Neither the first positional nor the named argument *length* are set.

Both the first positional nor the named argument *length* are set.

The value of *data* is an empty string.
