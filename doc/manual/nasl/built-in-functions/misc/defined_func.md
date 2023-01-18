# defined_func

## NAME

**defined_func** - check if a given function is defined

## SYNOPSIS

*bool* **defined_func**(0: *string*);

**defined_func** takes 1 positional argument.

## DESCRIPTION

Returns true when given function name is defined as a function otherwise false.

## RETURN VALUE

true when the function is defined otherwise false.

## ERRORS

Returns NULL when given data is null.

## EXAMPLES

```cpp
if (defined_func("display"))
  display('defined');
```
