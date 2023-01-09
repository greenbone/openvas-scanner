# raw_string

## NAME

**raw_string** - transforms any input into a string

## SYNOPSIS

*string* **raw_string**(*any*...);

**raw_string** takes any number of arguments.

## DESCRIPTION

This function takes any number of arguments of any time and transforms them into a string. The conversion of different types are:
- *int*: is converted to its corresponding ASCII character
- *string*: is not converted, it is taken, as it is
- *array*: is converted into its readable form
- *NULL*: does not convert to anything
- *bool*: is converted into the ASCII character corresponding to 0 or 1 for *FALSE* or *TRUE* respectively
- undefined variables are just skipped

The created string can have a maximum size of 32768. If, during any conversion, the string would become larger than this, the further processing is stopped, an error message is printed and the string, generated at this point, is returned.

This function is similar to **[strcat(3)](strcat.md)** and **[string(3)](string.md)**.

## RETURN VALUE

All given arguments are converted to *string* and concatenated in their given order.


## SEE ALSO

**[strcat(3)](strcat.md)**, **[string(3)](string.md)**
