# mktime

## NAME

**mktime** - takes seven named arguments sec, min, hour, mday, mon, year, isdst and returns the Unix time.

## SYNOPSIS

*int* **mktime**(arr|dict);

**mktime** takes seven named arguments sec, min, hour, mday, mon, year, isdst and returns the Unix time.

## DESCRIPTION

Takes:

- `sec` - seconds 0-60
- `min` - minutes 0-60
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

**[gettimeofday(3)](gettimeofday.md)**,
**[localtime(3)](localtime.md)**,
**[unixtime(3)](unixtime.md)**,
