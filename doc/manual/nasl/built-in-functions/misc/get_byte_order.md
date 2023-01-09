# get_byte_order

## NAME

**get_byte_order** - returns 1 on little-endian, 0 bid-endian

## SYNOPSIS

*bool* **get_byte_order**();

**get_byte_order** - returns 1 on little-endian, 0 bid-endian

## DESCRIPTION

Returns the byte order of the system. True when little-endian and false when big-endian.


## Returns 

1 when little-endian

0 when bid-endian
## EXAMPLES

```cpp
let le = get_byte_order();
```
