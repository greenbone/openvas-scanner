# bf_cbc_decrypt

## NAME

**bf_cbc_decrypt** - decrypts given data with blowfish CBC mode.

## SYNOPSIS

*str* **bf_cbc_decrypt**(key:str, iv: str, data: str);

**bf_cbc_decrypt** decrypts given data with blowfish CBC mode.

## DESCRIPTION
decrypt the given data using the blowfish algorithm in CBC mode.

The key must be 16 bytes long. 
The iv must be at least 8 bytes long. 
Data must be a multiple of 8 bytes long.

## RETURN VALUE

The return value is an array a with a[0] being the decrypted data and a[1] the new initialization vector to use for the next part of the data.
## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[bf_cbc_encrypt(3)](bf_cbc_encrypt.md)**,
