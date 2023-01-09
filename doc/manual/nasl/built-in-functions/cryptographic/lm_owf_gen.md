# lm_owf_gen

## NAME

**lm_owf_gen** - takes a unnamed parameter and returns LanMan one way hash.
## SYNOPSIS

*str* **lm_owf_gen**(str);

**lm_owf_gen** It takes one unnamed argument.

## DESCRIPTION

lm_owf_gen is a type of hash function.


## RETURN VALUE

lm_owf_gen hash

## ERRORS

Returns NULL when given data is null or when the algorithm is not supported by the installed gcrypt library.

## EXAMPLES

```cpp
hash = lm_owf_gen("test");
```

## SEE ALSO

**[nt_owf_gen(3)](nt_owf_gen.md)**,
**[ntv2_owf_gen(3)](ntv2_owf_gen.md)**,
