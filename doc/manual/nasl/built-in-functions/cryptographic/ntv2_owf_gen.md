# ntv2_owf_gen

## NAME

**ntv2_owf_gen** - takes fiven named arguments owf, login, domain, length, insert_hexzeros to generate the NTLMv2 of a users's password.

## SYNOPSIS

*str* **ntv2_owf_gen**(owf: str, login: str, domain: str, length int, insert_hexzeros str);

**ntv2_owf_gen** It takes fiven named arguments owf, login, domain, length, insert_hexzeros to generate the NTLMv2 of a users's password.

## DESCRIPTION

ntv2_owf_gen generates the ntv2_owf_gen based on the given arguments.


## RETURN VALUE

ntv2_owf_gen

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[lm_owf_gen(3)](lm_owf_gen.md)**,
**[nt_owf_gen(3)](nt_owf_gen.md)**,
