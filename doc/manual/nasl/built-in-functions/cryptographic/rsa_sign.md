# rsa_sign

## NAME

**rsa_sign** - signs data with the given private RSA key.

## SYNOPSIS

*str* **rsa_sign**(data: str, priv: str, passphrase: str);

**rsa_sign** signs data with the given private RSA key.

## DESCRIPTION

Signs the data with the private RSA key `priv` given in PEM format. 

The passphrase is the password needed to decrypt the private key.


## RETURN VALUE
Returns the signed data.

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[rsa_private_decrypt(3)](rsa_private_decrypt.md)**,
**[rsa_public_decrypt(3)](rsa_public_decrypt.md)**,
**[rsa_public_encrypt(3)](rsa_public_encrypt.md)**,
