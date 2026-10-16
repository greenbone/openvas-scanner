# MD4(3nasl)

## NAME

**MD4** - takes a unnamed paramaeter and return MD4 hash.
## SYNOPSIS

*str* **MD4**(str);

**MD4** It takes one unnamed argument.

## DESCRIPTION

MD4 is a type of hash function.


## RETURN VALUE

MD4 hash

## ERRORS

Returns NULL when given data is null or when the algorithm is not supported by the installed gcrypt library.

## EXAMPLES

```cpp
hash = MD4("test");
```

## SEE ALSO

**[MD2(3nasl)](MD2.md)**,
**[MD5(3nasl)](MD5.md)**,
**[NTLMv1_HASH(3nasl)](NTLMv1_HASH.md)**,
**[NTLMv2_HASH(3nasl)](NTLMv2_HASH.md)**,
**[RIPEMD160(3nasl)](RIPEMD160.md)**,
**[SHA1(3nasl)](SHA1.md)**,
**[SHA256(3nasl)](SHA256.md)**,
**[SHA512(3nasl)](SHA512.md)**,
