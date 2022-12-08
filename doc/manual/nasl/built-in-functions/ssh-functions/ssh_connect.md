# ssh_connect

## NAME

**ssh_connect** - connect ot the target via TCP and setup an SSH connection

## SYNOPSIS

*int* **ssh_connect**(socket: *int*, port: *int*, keytype: *string*, csciphers: *string*, scciphers: *string*, timeout: *int*);

**ssh_connect** takes up to 5 named arguments.

## DESCRIPTION

This function is used to either establish a new TCP connection or use a socket, that is already in use to setup a new SSH connection. **ssh_disconnect(3)** hast to be called to close the connection.

If the optional *socket* parameter is set, it is used instead of creating a new TCP connection. It contains *int* corresponding to an active socket.

The optional *port* parameter contains the port for the SSH connection. It is not needed if the *socket* parameter was set. If bot *port* and *socket* parameters are missing a fallback port is used instead. This is either a port set in the preferences, a port set within the kb in `Services/ssh` or the default SSH port 22.

The optional *keytype* parameter contains a comma separated list of preferred server host key types.
Example: `"ssh-rsa,ssh-dss"`

The optional *csciphers* parameter contains the client-to-server ciphers in a comma-separated list.

The optional *scciphers* parameter contains the server-to-client ciphers in a comma-separated list.

The optional *timeout* parameter defines a timeout for the connection in seconds. If not given, it is set to 10 seconds (defined by **libssh** internally)

## RETURN

A positive *int* >0 representing a session ID, 0 when unable to connect and *NULL* on an internal error.

## ERROR

The following errors will result in NULL value returned:

Failed to allocate a new SSH session

Failed to set SSH connection timeout

Failed to set SSH hostname. The hostname is set automatically and is defined with the scanned target.

Failed to disable SSH known_hosts, internal error

Failed to set SSH key type

Failed to set client to server ciphers

Failed to set server to client ciphers

Failed to set SSH port

No space left in SSH session table, internal error

## SEE ALSO

**[ssh_disconnect(3)](ssh_disconnect.md)**