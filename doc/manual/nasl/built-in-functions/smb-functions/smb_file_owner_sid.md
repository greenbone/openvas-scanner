# smb_file_owner_sid

## NAME

**smb_file_owner_sid** - get the owner SID of a file

## SYNOPSIS

*string* **smb_file_owner_sid**(smb_handle: *int*, filename: *string*);

**smb_file_owner_sid** takes two named arguments.

## DESCRIPTION

This function checks the owner of a file. A owner is specified by its SID.

The named argument *smb_handle* is an *int* representing a connection to a SMB service. This connection can be opened with the **[smb_connect(3)](smb_connect.md)** functions.

The named argument *filename* is a *string* containing the filename.

## RETURN VALUE

The SID of a owner of the given file as *string* or *NULL* on error.

## ERRORS

One of the arguments is either missing, empty or invalid.

File does not exist.

## SEE ALSO

**[smb_connect(3)](smb_connect.md)**
