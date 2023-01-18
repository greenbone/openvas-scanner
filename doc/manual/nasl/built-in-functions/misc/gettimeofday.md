# gettimeofday

## NAME

**gettimeofday** - get the number of seconds and microseconds since 1970-01-01

## SYNOPSIS

*str* **gettimeofday**();

**gettimeofday** takes no arguments

## DESCRIPTION

Returns the seconds and microseconds counted from 1st January 1970. It formats a string containing the seconds separated by a `.` followed by the microseconds.

For example: “1067352015.030757” means 1067352015 seconds and 30757 microseconds.

## RETURN VALUE

Returns the seconds and microseconds counted from 1st January 1970. It formats a string containing the seconds separated by a `.` followed by the microseconds.

For example: “1067352015.030757” means 1067352015 seconds and 30757 microseconds.

## EXAMPLES

```cpp
display(gettimeofday());
```
