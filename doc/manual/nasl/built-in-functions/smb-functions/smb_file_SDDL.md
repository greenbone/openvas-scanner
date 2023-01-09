# smb_file_SDDL

## NAME

**smb_file_SDDL** - obtain Security Descriptor in SDDL format

## SYNOPSIS

*string* **smb_file_SDDL**(smb_handle: *int*, filename: *string*);

**smb_file_SDDL** takes two named arguments.

## DESCRIPTION

This function checks the security descriptor of a file and obtains it in the SDDL format. SDDL is th Security Descriptor Definition Language and is used for e.g. the Access Control List (ACL) in the registry.

For more information about SDDL see [https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format].

The named argument *smb_handle* is an *int* representing a connection to a SMB service. This connection can be opened with the **[smb_connect(3)](smb_connect.md)** functions.

The named argument *filename* is a *string* containing the filename.

## RETURN VALUE

The security descriptor in SDDL format of the given file as *string* or *NULL* on error.

## ERRORS

One of the arguments is either missing, empty or invalid.

File does not exist.

## SEE ALSO

**[smb_connect(3)](smb_connect.md)**
