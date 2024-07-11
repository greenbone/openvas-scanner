# rsa_public_decrypt

## NAME

**rsa_public_decrypt** - decrypts provided data with the public RSA key given by e and d. Returns the decrypted data.

## SYNOPSIS

*str* **rsa_public_decrypt**(sig: str, e: str, n: str);

**rsa_public_decrypt** decrypts provided data with the public RSA key given by e and n. Returns the decrypted data.

## DESCRIPTION
Decrypts provided sig with the public RSA key given by e and n. Returns the decrypted data.

- sign: the data to encrypt
- e: part of the public rsa key
- n: part of the public rsa ket


## RETURN VALUE

Decrypted data
## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[rsa_private_decrypt(3)](rsa_private_decrypt.md)**,
**[rsa_public_encrypt(3)](rsa_public_encrypt.md)**,
**[rsa_sign(3)](rsa_sign.md)**,
