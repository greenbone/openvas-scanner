# isotime_scan

## NAME

**isotime_scan** - convert a string into an ISO time string

*string* **isotime_scan**(0: *string*);

**isotime_scan** takes 1 positional argument.

## DESCRIPTION

Convert a standard isotime (`yyyymmddThhmmss`) or a human readable variant (`yyyy-mm-dd[ hh[:mm[:ss]]]`) into the standard isotime (`yyyymmddThhmmss`).

The first unnamed argument is a *string* containing the string to convert.

## RETURN VALUE

The standard ISO time as *string* or *NULL* on error.

## ERRORS

First unnamed argument is missing.

Given string is too short.

Unable to convert string.
