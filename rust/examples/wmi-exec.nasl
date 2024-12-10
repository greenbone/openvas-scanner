login       = string( get_kb_item( "KRB5/login_filled/0" ) );
password    = string( get_kb_item( "KRB5/password_filled/0" ) );
realm = string( get_kb_item( "KRB5/realm_filled/0" ) );
kdc         = string( get_kb_item( "KRB5/kdc_filled/0" ) );
host        = ip_reverse_lookup();
cmd = 'powershell -Command "& {Get-Process}"';

result = win_cmd_exec(cmd:cmd, password:password, username:login, realm: realm, kdc: kdc, host:host);
display(result);
