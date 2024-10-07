display('do more hate-driven development');
result = krb5_gss_init();
if (krb5_is_failure(result)) {
	display('oh nooo, unable to init gss context');
	exit(42);
}
display("Got context, the easiest part is done.");
display("Keep in mind that gss_init does override previous context.");
#result = krb5_gss_prepare_context(realm: 'KBKERB.LOCAL', host: 'WIN-MPDRO9RF6Q8.gbkerb.local', service: 'cifs', user: 'gbadmin', password: '*********');
result = krb5_gss_prepare_context();
if (krb5_is_failure()) {
	display('oh nooo, unable to authenticate, did you check vpn? Yes, oh.');
	exit(42);
}
display("We got authenticated.... keep in mint that the first update context must be without data ...");
result = krb5_gss_update_context();
if (krb5_is_failure()) {
	display('oh nooo, unable to initially update context, did you check vpn? Yes, oh.');
	exit(42);
}
if (krb5_gss_update_context_needs_more()) {
	display('continue to send data to update_context...');
}

out = krb5_gss_update_context_out();
if (out) {
	display(hexstr(out));
} else {
	display('no data?!');
}

