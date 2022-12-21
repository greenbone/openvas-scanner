# keys

## NAME

**keys** - returns an array with the keys of a dict

## SYNOPSIS

*arr* **keys**(dict);

**keys** - returns an array with the keys of a dict

## DESCRIPTION

Keys returns an array with the keys of a dict.

## Returns

An array of used keys within a dict or NULL when the argument is not a dict/array.

## EXAMPLES

```cpp
a["test"] = 2;
a[1] = 3;

display(keys(a));
```
