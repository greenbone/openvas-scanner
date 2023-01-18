# sftp_enabled_check

## NAME

**sftp_enabled_check** - checks if SFTP is enabled on the target system

## SYNOPSIS

*int* **sftp_enabled_check**(*int*);

**sftp_enabled_check** takes one positional argument

## DESCRIPTION

SFTP stands for SSH/Secure File Transfer Protocol. This function checks, if this protocol is enabled on the target system.

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

0 on success, <0 or *NULL* on failure.
The reason for failure can be extracted from the return value.
- NULL indicates that either the positional argument was missing or the session ID is invalid
- <0 indicates an error within **sftp_new** or **sftp_init**, see **libssh** for more detail.


## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**
