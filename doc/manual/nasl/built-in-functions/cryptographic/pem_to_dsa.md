# pem_to_dsa

## NAME

**pem_to_dsa** - reads the private key in pem format to return the `x` parameter of the DSA key.

## SYNOPSIS

*str* **pem_to_dsa**(priv: str, passphrase: str);

**pem_to_dsa** reads the private key in pem format to return the `x` parameter of the DSA key.

## DESCRIPTION

Reads the private key from the `priv` which contains a private DSA key in PEM format. 

`passphrase` is the password needed to decrypt the private key. 


## RETURN VALUE

Returns the parameter `x` of the DSA key as an MPI.

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[pem_to_rsa(3)](pem_to_rsa.md)**,
