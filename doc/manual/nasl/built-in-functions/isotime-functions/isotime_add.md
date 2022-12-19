# isotime_add

## NAME

**isotime_add** - add years, days or seconds to an ISO time string

## SYNOPSIS

*string* **isotime_add**(0: *string*, years: *int*, days: *int*, seconds: *int*);

**isotime_add** takes 1 positional and up to 3 named arguments.

## DESCRIPTION

Adds given years, days and seconds to a given ISO time string.

The first positional argument is a *string* containing an ISO time string.

The named argument *years* is an *int* containing the number of years to add to the ISO time string

The named argument *days* is an *int* containing the number of days to add to the ISO time string

The named argument *seconds* is an *int* containing the number of seconds to add to the ISO time string

## RETURN VALUE

The resulting ISO time as *string* or *NULL* on error

## ERRORS

The first positional argument containing the ISO time string is missing or invalid.

The result would overflow, i.e. year >9999.
