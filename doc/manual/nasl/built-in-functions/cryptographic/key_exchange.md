# key_exchange

## NAME

**key_exchange** - takes three named arguments cryptkey, session_key, nt_hash

## SYNOPSIS

*str* **key_exchange**(cryptkey: str, session_key: str, nt_hash: str);

**key_exchange** It takes three named arguments cryptkey, session_key, nt_hash.

## DESCRIPTION

key_exchange uses the given cryptkey, session key as well as password hash to generate an authentication key.


## RETURN VALUE

authentication key.

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[NTLMv1_HASH(3)](NTLMv1_HASH.md)**,
**[NTLMv2_HASH(3)](NTLMv2_HASH.md)**,
**[nt_owf_gen(3)](nt_owf_gen.md)**,
**[ntlm2_response(3)](ntlm2_response.md)**,
**[ntlm_response(3)](ntlm_response.md)**,
**[ntlmv2_response(3)](ntlmv2_response.md)**,
**[ntv2_owf_gen(3)](ntv2_owf_gen.md)**,
