# bn_random

## NAME

**bn_random** - generates a random big number

## SYNOPSIS

*str* **bn_random**(need: int);

**bn_random** takes one named argument

## DESCRIPTION

This function generates a big number (bn) with the given amount of bits.
As this function generates the number as bytes, it actually takes the number of bits, divides them by 8
and rounds them up. It does not only generate the desired number of bits for the last byte, but a whole
random byte.

A big number is an integer, that is probably to big for any primitive data type. In case of the
c implementation the mpi (multi-precision integer) type of libgcrypt was used.


## RETURN VALUE

A random big number as bytes

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[bn_cmp(3)](bn_cmp.md)**,
