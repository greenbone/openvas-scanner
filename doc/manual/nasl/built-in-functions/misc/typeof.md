# typeof

## NAME

**typeof** - returns the type of given unnamed argument.

## SYNOPSIS

*str* **typeof**(any);

**typeof** returns the type of given unnamed argument.

## DESCRIPTION

Returns the type of the given argument.

## RETURN VALUE

Return 
- "undef" if the argument is not initialized,
- "int" if the argument is an integer,
- "string" if the argument is a string,
- "data" if the argument is argument is string based on `''`
- "unknown" if the argument is of an unknown type

## EXAMPLES

```cpp
display(typeof('a'));
```
