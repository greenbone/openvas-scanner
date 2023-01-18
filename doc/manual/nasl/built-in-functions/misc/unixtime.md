# unixtime

## NAME

**unixtime** - returns the unix time (number of seconds since 1970-01-01).

## SYNOPSIS

*int* **unixtime**();

**unixtime** returns the unix time (number of seconds since 1970-01-01).

## DESCRIPTION

Returns the seconds counted from 1st January 1970 as an integer.


## RETURN VALUE

Returns the seconds counted from 1st January 1970 as an integer.


## EXAMPLES

```cpp
display(unixtime());
```

## SEE ALSO

**[gettimeofday(3)](gettimeofday.md)**,
**[localtime(3)](localtime.md)**,
**[mktime(3)](mktime.md)**,
