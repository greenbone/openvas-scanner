# SPDX-FileCopyrightText: 2025 Greenbone AG
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#display('do more hate-driven-development');
#result = krb5_gss_init();
#if (krb5_is_failure(result)) {
#	display('oh nooo, unable to init gss context');
#	exit(42);
#}
#display("Got context, the easiest part is done.");
#display("Keep in mind that gss_init does override previous context.");
#result = krb5_gss_prepare_context(realm: 'KBKERB.LOCAL', host: 'WIN-MPDRO9RF6Q8.gbkerb.local', service: 'cifs', user: 'gbadmin', password: '*********');
result = krb5_gss_prepare_context();
if (krb5_is_failure(result)) {
	display('oh nooo, unable to authenticate, did you check vpn? Yes, oh.');
	exit(42);
}
display("We got authenticated.... keep in mint that the first update context must be without data ...");
result = krb5_gss_update_context();
if (krb5_is_failure(result)) {
	display('oh nooo, unable to initially update context, did you check vpn? Yes, oh.');
	exit(42);
}
# while (krb5_gss_update_context_needs_more()) {
# 	display('continue to send data to update_context...2');
# 	out = krb5_gss_update_context_out();
# 	soc = open_sock_tcp( 445 );
# 	if( ! soc ) {
# 	   display('no socket, exiting');
# 	   exit(42);
# 	}
# 	display('sending data to update context...');
# 	send(socket:soc, data:out);
# 	rec = recv(socket: sock);
# 	if (!rec) {
# 		display('no data received, exiting');
# 		# trying out ... it seems wrong, but who knows?
# 		exit(42);
# 	} 
# 	display('received data: ' + hexstr(rec));
# 	result = krb5_gss_update_context(rec);
# 	if (krb5_is_failure(result)) {
# 		display('oh nooo, unable to update context, did you check vpn? Yes, oh.');
# 		exit(42);
# 	}
# 	display('context updated');
# }

if (out) {
	display(hexstr(out));
} else {
	display('no data?!');
}


display("Forking");
sk = krb5_gss_session_key();
display("Error code: " + krb5_error_code_to_string());
display("Session key: " + hexstr(sk));
display("checking cleaning");
result = krb5_gss_init();
if (krb5_is_failure(result)) {
	display('oh nooo, unable to init gss context');
	exit(42);
}



# TODO: provide clean up function 
