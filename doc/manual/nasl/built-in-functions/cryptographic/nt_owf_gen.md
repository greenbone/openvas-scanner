# nt_owf_gen

## NAME

**nt_owf_gen** - takes an unnamed parameter and returns NT one way hash.

## SYNOPSIS

_str_ **nt_owf_gen**(str);

**nt_owf_gen** It takes one unnamed argument.

## DESCRIPTION

nt_owf_gen is a type of hash function. It produces the NT Hash (part of NTLM) for the
**[NTLMv1_HASH(3)](NTLMv1_HASH.md)** function. This is the counterpart to the
**[lm_owf_gen(3)](lm_owf_gen.md)** function.

NT - New Technology
OWF - one way function
gen - generate

## RETURN VALUE

NT hash

## ERRORS

Returns NULL when given data is null or when the algorithm is not supported by the installed gcrypt library.

## EXAMPLES

```cpp
hash = nt_owf_gen("test");
```

## SEE ALSO

**[NTLMv1_HASH(3)](NTLMv1_HASH.md)**
**[lm_owf_gen(3)](lm_owf_gen.md)**,
**[ntv2_owf_gen(3)](ntv2_owf_gen.md)**,
