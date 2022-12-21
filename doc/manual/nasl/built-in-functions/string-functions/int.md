# int

## NAME

**int** - converts a given argument into an integer

## SYNOPSIS

*int* **int**(0: *any*);

**int** takes 1 positional argument.

## DESCRIPTION

This function tries to convert any given parameter into an integer. If the conversion is not possible or no argument was given, a 0 is returned instead. If a string contains any non-numerical characters, it only converts, if the string starts with a numerical character and end at the first appearance of any non-numerical character. The TRUE value converts to 1, FALSE to 0. An array will always convert to 0.

The first positional argument is the value to convert to an *int*. It can be of any type.

## RETURN VALUE

The given value as *int* or 0 if conversion is not possible.
