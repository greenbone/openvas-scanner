# get_byte_order

## NAME

**get_byte_order** - get byte order of host system

## SYNOPSIS

*bool* **get_byte_order**();

**get_byte_order** takes no arguments

## DESCRIPTION

Returns the byte order of the system. True when little-endian and false when big-endian.


## Returns 

1 when little-endian

0 when bid-endian
## EXAMPLES

```cpp
let le = get_byte_order();
```
