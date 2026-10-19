# rsa_public_decrypt(3nasl)

## NAME

**rsa_public_decrypt** - decrypt provided data with the public RSA key given by e and d.

## SYNOPSIS

*str* **rsa_public_decrypt**(sig: str, e: str, n: str);

## DESCRIPTION

Decrypt provided sig with the public RSA key given by e and n. Return the decrypted data.

- sig: the data to encrypt
- e: part of the public rsa key
- n: part of the public rsa key

## RETURN VALUE

Decrypted data

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[rsa_private_decrypt(3nasl)](rsa_private_decrypt.md)**,
**[rsa_public_encrypt(3nasl)](rsa_public_encrypt.md)**,
**[rsa_sign(3nasl)](rsa_sign.md)**,
