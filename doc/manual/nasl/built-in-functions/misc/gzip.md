# gzip

## NAME

**gzip** - compress given data with gzip, when headformat is set to 'gzip' it uses gzipheader.

## SYNOPSIS

*str* **gzip**(str, headformat: str);

**gzip** - compress given data with gzip, when headformat is set to 'gzip' it uses gzipheader.

## DESCRIPTION

Compress given data with gzip, when headformat is set to 'gzip' it uses gzipheader.

## Returns

Compressed data.

## EXAMPLES

```cpp
compressed = gzip("very large", headformat: "gzip");
```

## SEE ALSO

**[gunzip(3)](gunzip.md)**,
