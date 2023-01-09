# insstr

## NAME

**insstr** - insert a string into another string, replacing the substring given with indices

## SYNOPSIS

*string* **insstr**(0: *string*, 1: *string*, 2: *int*, 3:*int*);

**insstr** takes up to 4 positional arguments.

## DESCRIPTION

This function inserts as string into another one. The position to insert the string is given by an index. This function is more a replacement than an insert as it replaces the string from the given index. An end index can be given, so only a specified slice of the string is replaced.

The first positional argument is the *string* to manipulate.

The second positional argument is the *string* which gets inserted into the first string.

The third positional argument is an *int* containing the start index from which on the original string is replaced.

The fourth positional argument is an *int* containing the end index for replaced string.

## RETURN VALUE

The manipulated *string* or *NULL* on error.
If the second given index is greaten than the first one, an error is printed and the string is truncated after the second given index.

## ERRORS

One of the first 3 arguments is missing.

The first index is greater than the size of the string.

## EXAMPLES

1. Example with only start index given:
```c#
a = insstr('aaaa', 'b', 2);

display(a);
# Displays aab
```

2. Example with start and end index given:
```c#
a = insstr('aaaa', 'b', 2, 2);

display(a);
# Displays aaba
```

3. Second index greater than the first one:
```c#
a = insstr('aaaa', 'b', 2, 1);
# Prints insstr: warning! 1st index 2 greater than 2nd index 1

display(a);
# Displays a
```
