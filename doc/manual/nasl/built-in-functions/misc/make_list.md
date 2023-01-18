# make_list

## NAME

**make_list** - takes any number of unnamed arguments and returns an array made from them.

## SYNOPSIS

*arr* **make_list**(any, ...);

**make_list** takes any number of unnamed arguments and returns an array made from them.

## DESCRIPTION

Takes any number of unnamed arguments and returns an array made from them.

It can also be used to flatten arrays.

## RETURN VALUE

Returns an indexed array made out of the arguments. The index starts at 0.


## EXAMPLES

```cpp
arr = [0, 2, 3];
a = make_list('a', 1, arr);
```

## SEE ALSO

**[make_array(3)](make_array.md)**,
