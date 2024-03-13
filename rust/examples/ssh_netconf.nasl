## This script uses a non-interactive (non pty) shell to elevate privileges
## in an ssh session.

include("ssh_func.inc");
include("misc_func.inc");

port = 830;
user = "user";
pass = "pass";

#session
display("Open connection");
sess = ssh_connect( port: port );
display("User Auth");
prompt = ssh_userauth(sess, login: user, password: pass);

display("Set subsystem");
sess = ssh_execute_netconf_subsystem (sess);
display("aaaa ",sess);

sleep(1);
hello = '<?xml version="1.0" encoding="UTF-8"?><hello><capabilities><capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability></capabilities></hello>\n]]>]]>';
display("\n\n sending hello ", hello);
ssh_shell_write(sess, cmd: hello);

rhello = ssh_shell_read (sess);
display("hello response: \n\n", rhello);

sleep(1);
cmd = "<rpc><get-software-information/></rpc>]]>]]>";
display("\n\n sending cmd ", cmd);
ssh_shell_write(sess, cmd: "<rpc><get-software-information/></rpc>]]>]]>");

sleep(1);
rcmd = ssh_shell_read (sess);
display("cmd response: \n\n", rcmd);

ssh_shell_close(sess);
ssh_disconnect(sess);
display("Finished, close, disconnect script 1");
