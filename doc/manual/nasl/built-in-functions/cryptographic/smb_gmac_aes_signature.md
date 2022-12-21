# smb_gmac_aes_signature

## NAME

**smb_gmac_aes_signature** - takes two named arguments key, buf, iv

## SYNOPSIS

*str* **smb_gmac_aes_signature**(key: str, buf: str, iv: str);

**smb_gmac_aes_signature** It takes four named arguments key, buf. iv

## DESCRIPTION

smb_gmac_aes_signature gets the gmac_aes signature based on the given arguments.


## RETURN VALUE

smb_gmac_aes_signature

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[smb_cmac_aes_signature(3)](smb_cmac_aes_signature.md)**,
