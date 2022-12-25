# smb_close

## NAME

**smb_close** - close SMB service handle

## SYNOPSIS

*bool* **smb_close**(smb_handle: *int*);

**smb_close** takes 1 named argument.

## DESCRIPTION

Closes an opened SMB service handle. A service handle can be opened with **[smb_connect(3)](smb_connect.md)**.

The named argument *smb_handle* is an *int* representing a connection to a SMB service. This connection can be opened with the **[smb_connect(3)](smb_connect.md)** functions.

## RETURN VALUE

*TRUE* on success, *FALSE* on failure.

## ERRORS

The named argument *smb_handle* is either missing or invalid.

## SEE ALSO

**[smb_connect(3)](smb_connect.md)**
