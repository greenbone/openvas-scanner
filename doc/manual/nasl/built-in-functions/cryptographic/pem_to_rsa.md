# pem_to_rsa

## NAME

**pem_to_rsa** - reads the private key in pem format to return the `d` parameter of the RSA key.

## SYNOPSIS

*str* **pem_to_rsa**(priv: str, passphrase: str);

**pem_to_rsa** reads the private key in pem format to return the `d` parameter of the RSA key.

## DESCRIPTION

Reads the private key from the `priv` which contains a private RSA key in PEM format. 

`passphrase` is the password needed to decrypt the private key. 


## RETURN VALUE

Returns the parameter ”d” of the RSA key as an MPI.

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[pem_to_dsa(3)](pem_to_dsa.md)**,
