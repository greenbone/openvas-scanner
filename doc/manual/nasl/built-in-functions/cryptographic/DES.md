# DES

## NAME

**DES** - takes a unnamed paramaeter and return DES hash.
## SYNOPSIS

*str* **DES**(str);

**DES** It takes one unnamed argument.

## DESCRIPTION

DES is a type of hash function.


## RETURN VALUE

DES hash

## ERRORS

Returns NULL when given data is null or when the algorithm is not supported by the installed gcrypt library.

## EXAMPLES

```cpp
hash = DES("test");
```
