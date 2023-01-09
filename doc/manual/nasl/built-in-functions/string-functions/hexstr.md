# hexstr

## NAME

**hexstr** - converts a string into a hexadecimal representation

## SYNOPSIS

*string* **hexstr**(0: *string*);

**hexstr** takes 1 positional argument.

## DESCRIPTION

This function converts each character of a string into its hexadecimal ASCII representation. The hexadecimals are written without any notation and space in between.

The first positional argument is the *string* to convert.

## RETURN VALUE

Hexadecimal representation of a given string as *string* or *NULL* on error.

## ERRORS

The first positional argument is missing.

## EXAMPLES

Conversion of a string:
```c#
a = hexstr('a!\n');

display(a);
# Displays 61210a
```