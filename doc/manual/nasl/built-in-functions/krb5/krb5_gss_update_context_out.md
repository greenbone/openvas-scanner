# krb5_gss_update_context_out

## NAME

**krb5_gss_update_context_out** - Returns the data for the application to send to the service.

## SYNOPSIS

*str* **krb5_gss_update_context_out**();


## DESCRIPTION

This function is used to get the data that the application should send to the service.

It should be called after `krb5_gss_update_context` to may get data that should be sent to the service. 

The caller must check if the result is not NULL before using it.

## RETURN VALUE

Returns the data that should be sent to the service or NULL if there is no data to send.

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
if ((out = krb5_gss_update_context_out())) {
	soc = open_sock_tcp( 445 );
	if( ! soc ) {
	   exit(42);
	}
	send(socket:soc, data:out);
}
```

