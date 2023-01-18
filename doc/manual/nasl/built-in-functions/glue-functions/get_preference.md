# get_preference

## NAME

**get_preference** - get a preference

## SYNOPSIS

*string* **get_preference**(0: *string*);

**get_preference** takes 1 positional argument

## DESCRIPTION

This function is necessary to retrieve some preferences. Its argument is:
0. name of the argument to retrieve

## RETURN VALUE

Value of the preference or *NULL* on error.

## ERRORS

- Preference does not exist

## EXAMPLES

1. Get the preference port_range:
```c#
p = get_preference(’port_range’); # returns something like 1-65535
```
