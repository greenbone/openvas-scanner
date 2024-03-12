# ssh_execute_netconf_subsytem

## NAME

**ssh_execute_netconf_subsytem** - execute the netconf subsystem on the ssh channel

## SYNOPSIS

*int* **ssh_execute_netconf_subsytem**(0: *int*);

**ssh_execute_netconf_subsytem** takes 1 positional.

## DESCRIPTION

Execute the NETCONF subsystem on the ssh channel

The positional argument contains a valid SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

A session ID corresponding to the shell instance as *int* or *NULL* or either an invalid SSH session ID or error.

## ERRORS

Unable to open a channel

Unable to execute netconf subsystem

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**
