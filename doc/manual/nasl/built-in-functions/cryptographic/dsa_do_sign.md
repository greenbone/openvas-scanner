# dsa_do_sign

## NAME

**dsa_do_sign** - computes DSA signature.

## SYNOPSIS

*str* **dsa_do_sign**(p: str, g: str, q: str, pub: str, priv: str, data: str);

**dsa_do_sign** computes DSA signature.

## DESCRIPTION

Computes the DSA signature of the hash in data using the private DSA key given by p, g, q, pub and priv. 


## RETURN VALUE
The return value is a 40 byte string encoding the two MPIs r and s of the DSA signature. The first 20 bytes are the value of r and the last 20 bytes are the value of s.

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[dsa_do_verify(3)](dsa_do_verify.md)**,
