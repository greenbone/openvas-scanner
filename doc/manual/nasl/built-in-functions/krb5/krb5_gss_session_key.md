# krb5_gss_session_key

## NAME

**krb5_gss_session_key** - Returns the session key or NULL if none was found.

## SYNOPSIS

*str* **krb5_gss_update_context_session_key**();


## DESCRIPTION

Returns the session key found within the context when the last `krb5_gss_update_context` was called. If no session key was found, NULL is returned.


## RETURN VALUE

Returns the session key or NULL if none was found.

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
if (krb5_is_failure(krb5_gss_update_context())) {
	exit(42);
}
if (krb5_update_context_needs_more()) {
   session_key = krb5_gss_session_key();
}
```

