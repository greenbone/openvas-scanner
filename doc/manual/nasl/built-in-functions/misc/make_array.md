# make_array

## NAME

**make_array** - takes any even number of unnamed arguments and returns an dictionary made from them

## SYNOPSIS

*dict* **make_array**(any, any, ...);

**make_array** takes any even number of unnamed arguments and returns an dictionary made from them.

## DESCRIPTION

Takes any even number of unnamed arguments and returns an dictionary made from them.
Each uneven argument will be the key while each even argument is the value.

## RETURN VALUE

Returns a dictionary made out of the arguments.

## Error

Drops the last value when the arguments are not even.

## EXAMPLES

```cpp
a = make_array('a', 1, 2, 3);
```

## SEE ALSO

**[make_list(3)](make_list.md)**,
