# substr

## NAME

**substr** - get a slice out of a string

## SYNOPSIS

*string* **substr**(0: *string*, 1: *int*, 2: *int*);

**substr** takes up to 3 positional arguments.

## DESCRIPTION

This function takes a slice out of a string with given indices.

The first positional argument is the *string* to get the slice from.

The second positional argument is the an *int* and contains the start index for the slice.

The optional third positional argument is an *int* and contains the end index for the slice. If not given it is set to the default. The default is the max value for an integer.

## RETURN VALUE

A slice of the given *string* or *NULL* on error.

## ERRORS

One of the first two positional arguments is missing.

The second positional argument is negative.
