# dh_compute_key

## NAME

**dh_compute_key** - computes the shared secret with the given shared parameter p and g, the servers public key and the clients private and public key.

## SYNOPSIS

*str* **dh_compute_key**(p: str, g: str, dh_server_pub: str, pub_key: str, priv_key:str);

**dh_compute_key** computes the shared secret with the given shared parameter p and g, the servers public key and the clients private and public key.

## DESCRIPTION

Computes the shared secret with:
- shared parameter p,
- shared parameter g, 
- the servers public key dh_server_pub,
- the clients public key pub_key
- the clients private key priv_key

## RETURN VALUE

Shared secret to be used as an MPI.

## ERRORS

Returns NULL when a given parameter is null.

## SEE ALSO

**[dh_generate_key(3)](dh_generate_key.md)**,
