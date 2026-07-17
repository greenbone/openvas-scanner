# lm_owf_gen

## NAME

**lm_owf_gen** - takes an unnamed parameter and returns LM one way hash.

## SYNOPSIS

_str_ **lm_owf_gen**(str);

**lm_owf_gen** It takes one unnamed argument.

## DESCRIPTION

lm_owf_gen is a type of hash function. It produces the LM Hash (part of NTLM) for the
**[NTLMv1_HASH(3)](NTLMv1_HASH.md)** function. This is the counterpart to the
**[nt_owf_gen(3)](nt_owf_gen.md)** function.

LM - Lan Manager
OWF - one way function
gen - generate

## RETURN VALUE

LM Hash

## ERRORS

Returns NULL when given data is null or when the algorithm is not supported by the installed gcrypt library.

## EXAMPLES

```cpp
hash = lm_owf_gen("test");
```

## SEE ALSO

**[NTLMv1_HASH(3)](NTLMv1_HASH.md)**,
**[nt_owf_gen(3)](nt_owf_gen.md)**,
**[ntv2_owf_gen(3)](ntv2_owf_gen.md)**,
