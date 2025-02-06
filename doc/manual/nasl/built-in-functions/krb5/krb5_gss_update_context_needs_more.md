# krb5_gss_update_context_needs_more

## NAME

**krb5_gss_update_context_needs_more** - Returns true when the previous `krb5_gss_update_context` requires further information/calls.

## SYNOPSIS

*int* **krb5_gss_update_context_needs_more**();

Returns 1 if the previous `krb5_gss_update_context` requires further information/calls, 0 otherwise.

## DESCRIPTION

This method is used to verify if the previous `krb5_gss_update_context` requires further information/calls.

## RETURN VALUE


Returns 1 if the previous `krb5_gss_update_context` requires further information/calls, 0 otherwise.

## EXAMPLES

```nasl
login       = string( get_kb_item( "KRB5/login_filled/0" ) );
password    = string( get_kb_item( "KRB5/password_filled/0" ) );
realm = string( get_kb_item( "KRB5/realm_filled/0" ) );
kdc         = string( get_kb_item( "KRB5/kdc_filled/0" ) );
host        = ip_reverse_lookup(); # must be a domain name.

result = krb5_gss_prepare_context(realm: realm, kdc: kdc, host: host, service: 'cifs', user: login, password: passwod);
if (krb5_is_failure(result)) {
	exit(42);
}
result = krb5_gss_update_context();
if (krb5_is_failure(result)) {
	exit(42);
}
if (krb5_gss_update_context_needs_more()) {
	exit(0);	
}
```

