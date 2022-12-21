# rsa_private_decrypt

## NAME

**rsa_private_decrypt** - decrypts provided data with the public RSA key given by e, n and d. Returns the decrypted data.

## SYNOPSIS

*str* **rsa_private_decrypt**(pad: bool, data: str, e: str, n: str, d: str);

**rsa_private_decrypt** decrypts provided data with the public RSA key given by e, n and d. Returns the decrypted data.

## DESCRIPTION
Encrypts provided data with the private RSA key given by e and n. Returns the encrypted data.

- pad: when true it is using padding\
- data: the data to encrypt
- e: part of the private rsa key
- n: part of the private rsa ket
- d: part of the private rsa ket


## RETURN VALUE

Decrypted data
## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[rsa_public_decrypt(3)](rsa_public_decrypt.md)**,
**[rsa_public_encrypt(3)](rsa_public_encrypt.md)**,
**[rsa_sign(3)](rsa_sign.md)**,
