# prf_sha256

## NAME

**prf_sha256** - takes four named arguments secret, seed, label, outlen
## SYNOPSIS

*str* **prf_sha256**(secret: str, seed: str, label: str, outlen: int);

**prf_sha256** It takes four named arguments secret, seed, label, outlen.

## DESCRIPTION

prf_sha256 is pseudo random function based on [rfc-2246§5](https://www.rfc-editor.org/rfc/rfc2246.html). 

It uses given seed and label as a basis for the pseudo random generator while the secret is the basis of the hash limited by the given outlen parameter.

The outlen is the length of the returned value in bytes.


## RETURN VALUE

prf_sha256 hash

## ERRORS

Returns NULL when a given parameter is null.

## EXAMPLES

```cpp
hash = prf_sha256(secret: "my_secret", seed: "a", label: "very secure", outlenL 48);
```

## SEE ALSO

**[prf_sha384(3)](prf_sha384.md)**,
**[tls1_prf(3)](tls1_prf.md)**,
