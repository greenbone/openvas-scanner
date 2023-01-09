# dh_generate_key

## NAME

**dh_generate_key** - takes three named arguments p, g and priv to generate the public key.

## SYNOPSIS

*str* **dh_generate_key**(p: str, g: str, priv: str);

**dh_generate_key** It takes three named arguments p, g and priv to generate the public key.

## DESCRIPTION

dh_generate_key generates the public key based on p, g and the private key.


## RETURN VALUE

public key
## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[dh_compute_key(3)](dh_compute_key.md)**,
