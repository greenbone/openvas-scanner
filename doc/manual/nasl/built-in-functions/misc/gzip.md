# gzip

## NAME

**gzip** - compress given data with gzip

## SYNOPSIS

*string* **gzip**(*string*, headformat: *string*);

**gzip** takes 1 positional and 1 named argument.

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
