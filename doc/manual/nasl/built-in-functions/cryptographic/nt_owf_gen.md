# nt_owf_gen

## NAME

**nt_owf_gen** - takes a unnamed paramaeter and returns NT one way hash.
## SYNOPSIS

*str* **nt_owf_gen**(str);

**nt_owf_gen** It takes one unnamed argument.

## DESCRIPTION

nt_owf_gen is a type of hash function.


## RETURN VALUE

nt_owf_gen hash

## ERRORS

Returns NULL when given data is null or when the algorithm is not supported by the installed gcrypt library.

## EXAMPLES

```cpp
hash = nt_owf_gen("test");
```

## SEE ALSO

**[lm_owf_gen(3)](lm_owf_gen.md)**,
**[ntv2_owf_gen(3)](ntv2_owf_gen.md)**,
