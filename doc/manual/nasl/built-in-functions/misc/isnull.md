# isnull

## NAME

**isnull** - check if a given value is NULL

## SYNOPSIS

*bool* **isnull**(*any*);

**isnull** takes 1 positional argument.

## DESCRIPTION
Returns true when the given unnamed argument is null.

Although semantically equal `isnull` behaves different than `== NULL` while 
```
if (0 == NULL)
  display('0 == NULL');
```

yields true and prints `0 == NULL`

```

if (isnull(0))
  display('0 == NULL');
```

yields false and does not print the message.

## RETURN VALUE

Returns true when the given unnamed argument is null.

## EXAMPLES

```cpp
if (!isnull(0))
  display('0 != NULL');
```
