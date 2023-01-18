# localtime

## NAME

**localtime** - returns an dict(mday, mon, min, wday, sec, yday, isdst, year, hour) based on optional given time in seconds and optinal flag if utc or not.

## SYNOPSIS

*string* **localtime**(*any*, utc: *bool*);

**localtime** takes 1 positional and 1 named argument.

## DESCRIPTION

Takes an optional argument based on seconds from 1970-01-01 in either int or a string in the form of `seconds.microseconds` as well as an flag if the given `Unix time` is in utc or not.

If the arguments are omitted than it uses the current time of the machine.

## RETURN VALUE

It returns a dictionary with the fields:

- `sec` The number of seconds after the minute, normally in the range 0 to 59, but can be up to 61 to allow for leap seconds.
- `min` The number of minutes after the hour, in the range 0 to 59.
- `hour` The number of hours past midnight, in the range 0 to 23.
- `mday` The day of the month, in the range 1 to 31.
- `mon` The number of the month, in the range 1 to 12.
- `year` The year (4 digits).
- `wday` The number of days since Sunday, in the range 0 to 6.
- `yday` The current day in the year, in the range 1 to 366.
- `isdst` A flag that indicates whether daylight saving time is in effect at the time described.

## EXAMPLES

```cpp
display(localtime());
```

## SEE ALSO

**[gettimeofday(3)](gettimeofday.md)**,
**[mktime(3)](mktime.md)**,
**[unixtime(3)](unixtime.md)**,
