# smb_connect

## NAME

**smb_connect** - opens a connection to a SMB service

## SYNOPSIS

*int* **smb_connect**(username: *string*, password: *string*, share: *string*);

**smb_connect** takes 3 named arguments.

## DESCRIPTION

This function opens a connection to a SMB service. A opened handler must be closed by calling **[smb_close(3)](smb_close.md)**.

The named argument *username* is a *string* containing the user to login onto the windows machine.

The named argument *password* is a *string* containing the password for the user.

The named argument *share* is a *string* containing the directory to run the smb commands in.

## RETURN VALUE

An *int* representing a SMB service handle or *NULL* on error.

## ERRORS

One of the arguments are missing.

Unable to connect to SMB service.

## SEE ALSO

**[smb_close(3)](smb_close.md)**
