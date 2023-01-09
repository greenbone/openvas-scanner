# smb_file_trustee_rights

## NAME

**smb_file_trustee_rights** - obtain file trustee SID with access mask

## SYNOPSIS

*string* **smb_file_trustee_rights**(smb_handle: *int*, filename: *string*);

**smb_file_trustee_rights** takes two named arguments.

## DESCRIPTION

This function obtains information about a files trustee SID with its access mask. The trustee SID corresponds to either an user or group. The access mask is a 32-bit value whose bits corresponds to the access rights supported by an object.
For more information see:
- access masks: [https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks]
- trustees SID: [https://learn.microsoft.com/en-us/windows/win32/secauthz/trustees]

The named argument *smb_handle* is an *int* representing a connection to a SMB service. This connection can be opened with the **[smb_connect(3)](smb_connect.md)** functions.

The named argument *filename* is a *string* containing the filename to get the permissions from.

## RETURN VALUE

The SID of a owner of the given file as *string* or *NULL* on error.

## ERRORS

One of the arguments is either missing, empty or invalid.

File does not exist.

## SEE ALSO

**[smb_connect(3)](smb_connect.md)**
