# max_index

## NAME

**max_index** - returns the length of an array.

## SYNOPSIS

*int* **max_index**(arr|dict);

**max_index** takes an array or dict and returns it length.

## DESCRIPTION

Takes any number of unnamed arguments and returns an array made from them.

It can also be used to flatten arrays.

## RETURN VALUE

Returns an indexed array made out of the arguments. The index starts at 0.

## Error

Returns NULL when given argument is neither a dict nor an array.

## EXAMPLES

```cpp
arr = [0, 2, 3];
len = max_index(arr);
```
