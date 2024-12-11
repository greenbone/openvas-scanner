# krb5_is_success

## NAME

**krb5_is_success** - Returns 1 if the last stored krb5 or given result code is a success, 0 otherwise.

## SYNOPSIS

*int* **krb5_is_success**(0: *int*);

**krb5_is_success** takes an optional positional argument.

## DESCRIPTION

Checks if given result code or cached result code is a success. If no result code is given, the last cached result code is used.

The cached result code reflects the error code of the last krb5 function call.


## RETURN VALUE

Returns 1 if the result code is a success, 0 otherwise.


## EXAMPLES

```c#
success = krb5_is_success();
display(success);
```


