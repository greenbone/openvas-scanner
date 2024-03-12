# SSH Functions

## GENERAL

Used for SSH connections and interactions

## TABLE OF CONTENT

- **[sftp_enabled_check](sftp_enabled_check.md)** - checks if SFTP is enabled on the target system
- **[ssh_connect](ssh_connect.md)** - connect ot the target via TCP and setup an SSH connection
- **[ssh_disconnect](ssh_disconnect.md)** - disconnect an open SSH connection
- **[ssh_get_auth_methods](ssh_get_auth_methods.md)** - get list of supported authentication schemes
- **[ssh_get_host_key](ssh_get_host_key.md)** - get the host key
- **[ssh_get_issue_banner](ssh_get_issue_banner.md)** - get the issue banner
- **[ssh_get_server_banner](ssh_get_server_banner.md)** - get the server banner
- **[ssh_get_sock](ssh_get_sock.md)** - get the corresponding socket to a SSH session ID
- **[ssh_login_interactive](ssh_login_interactive.md)** - starts an authentication process
- **[ssh_login_interactive_pass](ssh_login_interactive_pass.md)** - finishes an authentication process
- **[ssh_request_exec](ssh_request_exec.md)** - runs a command via SSH
- **[ssh_session_id_from_sock](ssh_session_id_from_sock.md)** - get the SSH session ID from a socket
- **[ssh_set_login](ssh_set_login.md)** - set the login name for authentication
- **[ssh_shell_close](ssh_shell_close.md)** - close an SSH shell
- **[ssh_shell_open](ssh_shell_open.md)** - requests an SSH shell
- **[ssh_shell_read](ssh_shell_read.md)** - read the output of a SSH shell
- **[ssh_shell_write](ssh_shell_write.md)** - write to a SSH shell
- **[ssh_userauth](ssh_userauth.md)** - authenticate a user on a SSH connection
- **[ssh_execute_netconf_subsytem](ssh_execute_netconf_subsytem.md)** - execute the netconf subsystem on the ssh channel
