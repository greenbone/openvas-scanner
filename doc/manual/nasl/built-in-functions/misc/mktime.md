# mktime

## NAME

**mktime** - takes seven named arguments sec, min, hour, mday, mon, year, isdst and returns the Unix time.

## SYNOPSIS

*int* **mktime**(arr|dict);

**mktime** - takes seven named arguments sec, min, hour, mday, mon, year, isdst and returns the Unix time.

## DESCRIPTION

Takes:
- `sec` - seconds 0-60
- `min` - mintues 0-60
- `hour` - hour 0-23
- `mday` - day of the month 0-31
- `mon` - month 1-12
- `year` - year four digits 
- `isdst` A flag that indicates whether daylight saving time is in effect at the time described.

Transforms those into the Unix time.


## RETURN VALUE
Returns a Unix time (the number of seconds since 1970-01-01).

## Error

Returns NULL when any given argument is invalid.

## EXAMPLES

```cpp
ut = mktime(sec: 10, min: 10, hour: 10, mday: 10, mon: 10, year: 2022, isdst: false);
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
