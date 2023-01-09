# smb_versioninfo

## NAME

**smb_versioninfo** - get a version string of the SMB implementation

## SYNOPSIS

*string* **smb_versioninfo**();

**smb_versioninfo** takes no arguments.

## DESCRIPTION

This function checks the current version of the SMB implementation and returns it. This can be used to check if functions are available in the current version. Can also be used to check if there is even any implementation for SMB functionality, as these are not mandatory for compiling the openvas-scanner. By default the openvas-scanner implementation just returns a *NULL* value for all functionalities. In order to use SMB **[openvas-smb](https://github.com/greenbone/openvas-smb)** has to be installed before.

## RETURN VALUE

The current version of the WMI implementation as *string* or *NULL* if there is none.
