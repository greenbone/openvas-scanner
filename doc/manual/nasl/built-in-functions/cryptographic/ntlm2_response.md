# ntlm2_response

## NAME

**ntlm2_response** - takes three named arguments cryptkey, password, nt_hash
## SYNOPSIS

*str* **ntlm2_response**(cryptkey: str, password: str, nt_hash: str);

**ntlm2_response** It takes three named arguments cryptkey, password, nt_hash to generate ntlm2 response.

The nt_hash is the `nt_owf_gen` response of the password given in password.

## DESCRIPTION

ntlm2_response generates the ntlm2_response based on the given arguments.


## RETURN VALUE

ntlm2_response

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[ntlm_response(3)](ntlm_response.md)**,
**[ntlmv2_response(3)](ntlmv2_response.md)**,
