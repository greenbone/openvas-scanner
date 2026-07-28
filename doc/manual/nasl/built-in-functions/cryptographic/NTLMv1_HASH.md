# NTLMv1_HASH

## NAME

**NTLMv1_HASH** - takes two named arguments cryptkey, passhash

## SYNOPSIS

_str_ **NTLMv1_HASH**(cryptkey: str, passhash: str);

**NTLMv1_HASH** It takes two named arguments cryptkey, passhash.

## DESCRIPTION

NTLMv1_HASH generates the NTLMv1_HASH based on the given arguments. To generate the passhash,
**[nt_owf_gen(3)](nt_owf_gen.md)** and **[lm_owf_gen(3)](lm_owf_gen.md)** should be used.

## RETURN VALUE

NTLMv1_HASH

## ERRORS

Returns NULL when a given parameter is null or the passhash does not have a length of 16.

## SEE ALSO

**[nt_owf_gen(3)](nt_owf_gen.md)**, **[lm_owf_gen(3)](lm_owf_gen.md)**, **[NTLMv2_HASH(3)](NTLMv2_HASH.md)**
