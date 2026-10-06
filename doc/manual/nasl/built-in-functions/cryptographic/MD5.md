# MD5(3nasl)

## NAME

**MD5** - takes a unnamed paramaeter and return MD5 hash.
## SYNOPSIS

*str* **MD5**(str);

**MD5** It takes one unnamed argument.

## DESCRIPTION

MD5 is a type of hash function.


## RETURN VALUE

MD5 hash

## ERRORS

Returns NULL when given data is null or when the algorithm is not supported by the installed gcrypt library.

## EXAMPLES

```cpp
hash = MD5("test");
```

## SEE ALSO

**[MD2(3nasl)](MD2.md)**,
**[MD4(3nasl)](MD4.md)**,
**[NTLMv1_HASH(3nasl)](NTLMv1_HASH.md)**,
**[NTLMv2_HASH(3nasl)](NTLMv2_HASH.md)**,
**[RIPEMD160(3nasl)](RIPEMD160.md)**,
**[SHA1(3nasl)](SHA1.md)**,
**[SHA256(3nasl)](SHA256.md)**,
**[SHA512(3nasl)](SHA512.md)**,
