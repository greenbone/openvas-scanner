# ntlm_response

## NAME

**ntlm_response** - takes four named arguments cryptkey, password, nt_hash, neg_flags
## SYNOPSIS

*str* **ntlm_response**(cryptkey: str, password: str, nt_hash: str, neg_flags: int);

**ntlm_response** It takes four named arguments cryptkey, password, nt_hash, neg_flags to generate ntlm response.

The nt_hash is the `nt_owf_gen` response of the password given in password.
The neg_flags must be a positive number and is used to determine if it is using a MD4 hash basis when set to `0x00000080` or a 128 bit unchanged basis when set differently.

## DESCRIPTION

ntlm_response generates the ntlm_response based on the given arguments.


## RETURN VALUE

ntlm_response

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[ntlm2_response(3)](ntlm2_response.md)**,
**[ntlmv2_response(3)](ntlmv2_response.md)**,
