# RIPEMD160(3nasl)

## NAME

**RIPEMD160** - takes a unnamed paramaeter and return RIPEMD160 hash

## SYNOPSIS

*str* **RIPEMD160**(str);

**RIPEMD160** It takes one unnamed argument.

## DESCRIPTION

RIPEMD160 is a type of hash function.


## RETURN VALUE

RIPEMD160 hash

## ERRORS

Returns NULL when given data is null or when the algorithm is not supported by the installed gcrypt library.

## EXAMPLES

```cpp
hash = RIPEMD160("test");
```

## SEE ALSO

**[MD2(3nasl)](MD2.md)**,
**[MD4(3nasl)](MD4.md)**,
**[MD5(3nasl)](MD5.md)**,
**[NTLMv1_HASH(3nasl)](NTLMv1_HASH.md)**,
**[NTLMv2_HASH(3nasl)](NTLMv2_HASH.md)**,
**[SHA1(3nasl)](SHA1.md)**,
**[SHA256(3nasl)](SHA256.md)**,
**[SHA512(3nasl)](SHA512.md)**,
