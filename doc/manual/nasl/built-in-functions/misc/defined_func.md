# defined_func

## NAME

**defined_func** - takes a unnamed string parameter as a function name to figure out if it is defined.

## SYNOPSIS

*bool* **defined_func**(str);

**defined_func** - takes a unnamed string parameter as a function name to figure out if it is defined.

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
