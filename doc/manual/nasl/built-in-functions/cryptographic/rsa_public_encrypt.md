# rsa_public_encrypt

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
- n: part of the public rsa ket


## RETURN VALUE

Encrypted data
## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[rsa_private_decrypt(3)](rsa_private_decrypt.md)**,
**[rsa_public_decrypt(3)](rsa_public_decrypt.md)**,
**[rsa_sign(3)](rsa_sign.md)**,
