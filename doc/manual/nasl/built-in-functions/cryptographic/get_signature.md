# get_signature

## NAME

**get_signature** - takes four named arguments key, buf, buflen, seq_number

## SYNOPSIS

*str* **get_signature**(key: str, buf: str, buflen: int, seq_number: int);

**get_signature** It takes four named arguments key, buf, buflen, seq_number.

## DESCRIPTION

get_signature gets the ntlmssp signature based on the given arguments.


## RETURN VALUE

get_signature

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[NTLMv1_HASH(3)](NTLMv1_HASH.md)**,
**[NTLMv2_HASH(3)](NTLMv2_HASH.md)**,
**[ntlm2_response(3)](ntlm2_response.md)**,
**[ntlm_response(3)](ntlm_response.md)**,
**[ntlmv2_response(3)](ntlmv2_response.md)**,
