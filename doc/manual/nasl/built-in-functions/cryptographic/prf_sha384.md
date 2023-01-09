# prf_sha384

## NAME

**prf_sha384** - takes four named arguments secret, seed, label, outlen
## SYNOPSIS

*str* **prf_sha384**(secret: str, seed: str, label: str, outlen: int);

**prf_sha384** It takes four named arguments secret, seed, label, outlen.

## DESCRIPTION

prf_sha384 is pseudo random function based on [rfc-2246§5](https://www.rfc-editor.org/rfc/rfc2246.html). 

It uses given seed and label as a basis for the pseudo random generator while the secret is the basis of the hash limited by the given outlen parameter. 


## RETURN VALUE

prf_sha384 hash

## ERRORS

Returns NULL when a given parameter is null.

## EXAMPLES

```cpp
hash = prf_sha384(secret: "my_secret", seed: "a", label: "very secure", outlenL 48);
```

## SEE ALSO

**[prf_sha256(3)](prf_sha256.md)**,
**[tls1_prf(3)](tls1_prf.md)**,
