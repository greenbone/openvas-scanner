# make_array

## NAME

**make_array** - takes any even number of unnamed arguments and returns an dictionary made from them.

## SYNOPSIS

*dict* **make_array**(any, any, ...);

**make_array** - takes any even number of unnamed arguments and returns an dictionary made from them.

## DESCRIPTION

Takes any even number of unnamed arguments and returns an dictionary made from them.
Each uneven argument will be the key while each even argument is the value.

## RETURN VALUE

Returns a dictionary made out of the arguments.

## Error

Returns NULL when the amount of arguments are not even.

## EXAMPLES

```cpp
a = make_array('a', 1, 2, 3);
```

## SEE ALSO

**[defined_func(3)](defined_func.md)**,
**[dump_ctxt(3)](dump_ctxt.md)**,
**[gettimeofday(3)](gettimeofday.md)**,
**[isnull(3)](isnull.md)**,
**[localtime(3)](localtime.md)**,
**[make_array(3)](make_array.md)**,
**[make_list(3)](make_list.md)**,
**[v(3)](v.md)**,
**[max_index(3)](max_index.md)**,
**[mktime(3)](mktime.md)**,
**[safe_checks(3)](safe_checks.md)**,
**[sleep(3)](sleep.md)**,
**[typeof(3)](typeof.md)**,
**[usleep(3)](usleep.md)**,
**[unixtime(3)](unixtime.md)**,
**[get_byte_order(3)](get_byte_order.md)**,
**[gzip(3)](gzip.md)**,
**[gunzip(3)](gunzip.md)**,
**[dec(3)](dec.md)**,
**[keys(3)](keys.md)**,
**[sort(3)](sort.md)**,
**[exit(3)](exit.md)**,
**[rand(3)](rand.md)**,
**[open_sock_kdc(3)](open_sock_kdc.md)**,
