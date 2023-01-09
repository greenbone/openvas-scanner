# strcat

## NAME

**strcat** - concatenate given values

## SYNOPSIS

*string* **strcat**(*any*...);

**strcat** takes any number of arguments

## DESCRIPTION

This function takes any argument of any type, converts them into strings and concatenates them. The conversion of the arguments have these rules:
- *int*: the decimal number is just converted into a string
- *string*: is just taken as it is
- *array*: is converted in its readable form
- *NULL*: is not converted into anything
- *bool*: *TRUE* is converted into "1" and *FALSE* into "0"
- undefined variables are just ignored

This function works similar to **[raw_string(3)](raw_string.md)** and the same as **[string(3)](string.md)**.

## RETURN VALUE

All given arguments are converted to *string* and concatenated in their given order.

## SEE ALSO

**[raw_string(3)](raw_string.md)**, **[string(3)](string.md)**
