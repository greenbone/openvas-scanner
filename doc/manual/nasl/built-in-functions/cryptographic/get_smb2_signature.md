# get_smb2_signature

## NAME

**get_smb2_signature** - takes two named arguments key, buf

## SYNOPSIS

*str* **get_smb2_signature**(key: str, buf: str);

**get_smb2_signature** It takes four named arguments key, buf.

## DESCRIPTION

get_smb2_signature gets the smb2 signature based on the given arguments.


## RETURN VALUE

get_smb2_signature

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[smb3kdf(3)](smb3kdf.md)**,
**[smb_cmac_aes_signature(3)](smb_cmac_aes_signature.md)**,
**[smb_gmac_aes_signature(3)](smb_gmac_aes_signature.md)**,
