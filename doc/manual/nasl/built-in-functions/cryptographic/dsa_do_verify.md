# dsa_do_verify

## NAME

**dsa_do_verify** - verifies that the DSA signature matches the hash based on the public DSA key. Returns 1 if the signature is valid otherwise 0.

## SYNOPSIS

*str* **dsa_do_verify**(p: str, g: str, q: str, pub: str, r: str, s: str, data: str);

**dsa_do_verify** verifies that the DSA signature matches the hash based on the public DSA key. Returns 1 if the signature is valid otherwise 0.

## DESCRIPTION

Verifies that the DSA signature given by r and s matches the hash given in data based on the public DSA key by p, g q and pub. 


## RETURN VALUE

Returns 1 if the signature is valid otherwise 0.

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[dsa_do_sign(3)](dsa_do_sign.md)**
