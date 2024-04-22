# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

## This shows a simple use case of the nasl ssh functions.

session_id = ssh_connect(port: 22, keytype: "ssh-rsa,ssh-dss");
display(session_id);
#prompt = ssh_login_interactive(session_id, login: "user");
#display(prompt);
#auth = ssh_login_interactive_pass(session_id, pass: "pass");
#a = ssh_set_login(session_id, login: "admin");
auth = ssh_userauth(session_id, login: "user", password: "pass");
display(auth);

#banner = ssh_get_issue_banner(session_id);
#display(banner);
#banner = ssh_get_server_banner(session_id);
#display(banner);

res = ssh_request_exec(session_id, cmd:"ls", stdout: 1, stderr: 1);
display(res);

#m = ssh_get_auth_methods(session_id);
#display(m);

#Check SFTP
#ret = sftp_enabled_check (session_id);
#display("SFTP: ", ret);

# get server pub key
#k = ssh_get_host_key(session_id);
#display(k);
#display(hexstr(k));

#shell = ssh_shell_open(session_id);
#display (shell);
#res = ssh_shell_write(session_id, cmd: "ls -al");
#display(res);
#sleep(1);
#buf = ssh_shell_read (session_id);
#display(buf);
#c = ssh_shell_close(session_id);
#display(c);

d = ssh_disconnect(session_id);
display(d);
