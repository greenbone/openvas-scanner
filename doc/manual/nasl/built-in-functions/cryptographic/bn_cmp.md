# bn_cmp

## NAME

**bn_cmp** - compares two big numbers

## SYNOPSIS

*str* **bn_cmp**(key1: str, key2: str);

**bn_cmp** It takes two named arguments

## DESCRIPTION

Compares two big numbers given as Bytes interpreted in big endian.

## RETURN VALUE

0 when key and key2 are equal, -1 when key1 < key2 and 1 when key1 > key2.

## SEE ALSO

**[bn_random(3)](bn_random.md)**,
