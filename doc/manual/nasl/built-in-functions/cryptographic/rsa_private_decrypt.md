# rsa_private_decrypt(3nasl)

## NAME

**rsa_private_decrypt** - decrypts provided data with the public RSA key given by e, n and d.

## SYNOPSIS

*str* **rsa_private_decrypt**(pad: bool, data: str, e: str, n: str, d: str);

## DESCRIPTION

Decrypts provided data with the public RSA key given by e, n and d. Return the decrypted data.

- pad: when true it is using padding\
- data: the data to decrypt
- e: part of the private rsa key
- n: part of the private rsa key
- d: part of the private rsa key

## RETURN VALUE

Decrypted data

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[rsa_public_decrypt(3nasl)](rsa_public_decrypt.md)**,
**[rsa_public_encrypt(3nasl)](rsa_public_encrypt.md)**,
**[rsa_sign(3nasl)](rsa_sign.md)**,
