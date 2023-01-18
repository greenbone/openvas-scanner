# gunzip

## NAME

**gunzip** - decompress given data.

## SYNOPSIS

*str* **gunzip**(data: str);

**gunzip** takes 1 named argument.

## DESCRIPTION

Decompresses given data.

## Returns

Decompressed data.

## EXAMPLES

```cpp
compressed = gunzip(gzip(data: "very large"));
```
