# keys

## NAME

**keys** - returns an array with the keys of a dict

## SYNOPSIS

*array* **keys**(*array*);

**keys** takes 1 positional argument.

## DESCRIPTION

Keys returns an array with the keys of a dict.
Memory for each key-value tuple is reserved separately and allocated memory do
not necessarily return contiguous memory addresses because of how dynamic
memory allocation works in C and how the operating system manages memory.
Therefore, key-value tuples do not necessarily keep the order in which
they were stored.

## Returns

An array of used keys within a dict or NULL when the argument is not a dict/array.

## EXAMPLES

```cpp
a["test"] = 2;
a[1] = 3;

display(keys(a));
```
