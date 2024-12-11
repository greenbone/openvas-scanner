# krb5_error_code_to_string

## NAME

**krb5_error_code_to_string** - Returns a string representation of either the given code or the cached code.

## SYNOPSIS

*str* **krb5_error_code_to_string**(int);


## DESCRIPTION

Returns a string representation of either the given code or the cached code.

The cached code reflects the error code of the last krb5 function call.


## RETURN VALUE

Returns a human readable version of the result code.

## EXAMPLES

```nasl
login       = string( get_kb_item( "KRB5/login_filled/0" ) );
password    = string( get_kb_item( "KRB5/password_filled/0" ) );
realm = string( get_kb_item( "KRB5/realm_filled/0" ) );
kdc         = string( get_kb_item( "KRB5/kdc_filled/0" ) );
host        = ip_reverse_lookup(); # must be a domain name.

result = krb5_gss_prepare_context(realm: realm, kdc: kdc, host: host, service: 'cifs', user: login, password: passwod);
if (krb5_is_failure(result)) {
        display(krb5_error_code_to_string(result));
}
display(krb5_error_code_to_string());
```

