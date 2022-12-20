# isnull

## NAME

**isnull** - returns true when the given unnamed argument is null.

## SYNOPSIS

*bool* **isnull**(any);

**isnull** - returns true when the given unnamed argument is null.

## DESCRIPTION
Returns true when the given unnamed argument is null.

Although semantically equal `isnull` behaves different than `== NULL` while 
```
if (0 == NULL)
  display('0 == NULL');
```

yields true and prints `0 == NULL`

```

if (isnull(0))
  display('0 == NULL');
```

yields false and does not print the message.

## RETURN VALUE

Returns true when the given unnamed argument is null.

## EXAMPLES

```cpp
if (!isnull(0))
  display('0 != NULL');
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
