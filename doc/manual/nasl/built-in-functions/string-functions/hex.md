# hex

## NAME

**hex** - converts an integer into a hexadecimal number

## SYNOPSIS

*string* **hex**(0: *int*);

**hex** takes 1 positional argument.

## DESCRIPTION

This function converts a given integer into a hexadecimal number. This function is very limited and only works properly for numbers from 0 to 255, as it always returns a string in the form 0x00.

The first unnamed argument is an *int*.

## RETURN VALUE

The hexadecimal number as *string* for numbers between 0 and 255 or *NULL* on error. -1 counts as error.
Numbers exceeding this limit starts from 0x00 or 0xff. For example the number -2 converts to 0xfe, the number 257 coverts to 0x01.

## ERRORS

The first positional argument is either missing or -1.
