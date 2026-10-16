# key_exchange(3nasl)

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

**[NTLMv1_HASH(3nasl)](NTLMv1_HASH.md)**,
**[NTLMv2_HASH(3nasl)](NTLMv2_HASH.md)**,
**[nt_owf_gen(3nasl)](nt_owf_gen.md)**,
**[ntlm2_response(3nasl)](ntlm2_response.md)**,
**[ntlm_response(3nasl)](ntlm_response.md)**,
**[ntlmv2_response(3nasl)](ntlmv2_response.md)**,
**[ntv2_owf_gen(3nasl)](ntv2_owf_gen.md)**,
