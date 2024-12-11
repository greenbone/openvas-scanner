# krb5_gss_init

## NAME

**krb5_gss_init** - initialize the krb5 GSS-API library

## SYNOPSIS

*int* **krb5_gss_init**();

**krb5_gss_init** takes no arguments.

## DESCRIPTION

Initializes the krb5 GSS-API library. This function can be ommited when gss_prepare_context is called.

When there is an already initialized context it will be destroyed and a new one will be created.

## RETURN VALUE

Returns 0 on success otherwise it is an failure.


## EXAMPLES

```c#
result = krb5_gss_init();
if (krb5_is_failure(result)) {
	exit(42);
}
```


