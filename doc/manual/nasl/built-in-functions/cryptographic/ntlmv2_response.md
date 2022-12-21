# ntlmv2_response

## NAME

**ntlmv2_response** - takes six named arguments cryptkey, user, domain, ntlmv2_hash, address_list, address_list_len to generate a ntlmv2 response.
## SYNOPSIS

*str* **ntlmv2_response**(cryptkey: str, user: str, domain: str, ntlmv2_hash: str, address_list: str, address_list_len: int);

**ntlmv2_response** It takes six named arguments cryptkey, user, domain, ntlmv2_hash, address_list, address_list_len to generate a ntlmv2 response.

The ntlmv2_hash is usually the output of `ntv2_owf_gen`. 

## DESCRIPTION

ntlmv2_response generates the ntlmv2_response based on the given arguments to calculate the session_key.


## RETURN VALUE

ntlmv2_response

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[NTLMv1_HASH(3)](NTLMv1_HASH.md)**,
**[NTLMv2_HASH(3)](NTLMv2_HASH.md)**,
**[ntlm2_response(3)](ntlm2_response.md)**,
**[ntlm_response(3)](ntlm_response.md)**,
