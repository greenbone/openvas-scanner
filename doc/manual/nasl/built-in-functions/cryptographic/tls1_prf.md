# tls1_prf

## NAME

DEPRECATED

**tls1_prf** - takes four named arguments secret, seed, label, outlen. This function is deprecated and will not longer be supported!
## SYNOPSIS

*str* **tls1_prf**(secret: str, seed: str, label: str, outlen: int);

**tls1_prf** It takes four named arguments secret, seed, label, outlen.

## DESCRIPTION

tls1_prf is pseudo random function based on [rfc-4346§5](https://www.rfc-editor.org/rfc/rfc4346.html). 

It uses given seed and label as a basis for the pseudo random generator while the secret is the basis of the hash limited by the given outlen parameter. 

## DEPRECATED

This function is deprecated and **[prf_sha256(3)](prf_sha256.md)** or **[prf_sha384(3)](prf_sha384.md)** should be used instead.

## RETURN VALUE

tls1_prf hash

## ERRORS

Returns NULL when a given parameter is null.

## EXAMPLES

```cpp
hash = tls1_prf(secret: "my_secret", seed: "a", label: "very secure", outlenL 48);
```

## SEE ALSO

**[prf_sha256(3)](prf_sha256.md)**,
**[prf_sha384(3)](prf_sha384.md)**,
