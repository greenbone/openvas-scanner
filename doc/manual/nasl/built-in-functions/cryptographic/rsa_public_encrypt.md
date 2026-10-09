# rsa_public_encrypt(3nasl)

## NAME

**rsa_public_encrypt** - encrypts provided data with the public RSA key given by e and n. Returns the encrypted data.

## SYNOPSIS

*str* **rsa_public_encrypt**(pad: bool, data: str, e: str, n: str);

**rsa_public_encrypt** encrypts provided data with the public RSA key given by e and n. Returns the encrypted data.

## DESCRIPTION
Encrypts provided data with the public RSA key given by e and n. Returns the encrypted data.

- pad: when true it is using padding\
- data: the data to encrypt
- e: part of the public rsa key
- n: part of the public rsa key


## RETURN VALUE

Encrypted data
## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[rsa_private_decrypt(3nasl)](rsa_private_decrypt.md)**,
**[rsa_public_decrypt(3nasl)](rsa_public_decrypt.md)**,
**[rsa_sign(3nasl)](rsa_sign.md)**,
