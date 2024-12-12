# krb5_gss_update_context

## NAME

**krb5_gss_update_context** - Updates the context with the provided data and caches the output for the application.

## SYNOPSIS

*int* **krb5_gss_update_context**(str);

Has an optional positional argument that contains the byte array to send to the KDC.

## DESCRIPTION

Initializes the security context with the provided data and caches the output for the application.

When the service is `cifs` the first call of `krb5_gss_update_context` must be without data.

As this method returns an error code the caller must get the data for the application via `krb5_gss_update_context_out()`.

To verify if the process requires further step the caller must call `krb5_gss_update_context_needs_more()`.


## RETURN VALUE

Returns 0 on success otherwise it is an failure.


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
while (krb5_gss_update_context_needs_more()) {
	out = krb5_gss_update_context_out();
	soc = open_sock_tcp( 445 );
	if( ! soc ) {
	   exit(42);
	}
	send(socket:soc, data:out);
	rec = recv(socket: sock);
	if (!rec) {
		exit(42);
	} 
	result = krb5_gss_update_context(rec);
	if (krb5_is_failure(result)) {
		exit(42);
	}
}
```

