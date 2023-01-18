# sort

## NAME

**sort** - sorts the value of a dict/array. WARNING: drops the keys of a dict and returns an array.

## SYNOPSIS

*arr* **sort**(arr);

**sort** sorts the value of a dict/array. WARNING: drops the keys of a dict and returns an array.

## DESCRIPTION

Sorts the values of an array in ascending order. When given a dict it will drop the keys and returns an indexed array instead.

So when given an dict:

```
a["test"] = 1;
a[1] = 0;
b = sort(a);
```
than b will be
```
[0: 0, 1: 1]
```

and the key `test` will be dropped.

## Returns

An ascending sorted array. 

## EXAMPLES

```cpp
a["test"] = 2;
a[1] = 3;

display(sort(a));
```

## SEE ALSO

**[make_list(3)](make_list.md)**,
