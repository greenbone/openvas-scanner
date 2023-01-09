# wmi_versioninfo

## NAME

**wmi_versioninfo** - get a version string of the WMI implementation

## SYNOPSIS

*string* **wmi_versioninfo**();

**wmi_versioninfo** takes no arguments.

## DESCRIPTION

This function checks the current version of the WMI implementation and returns it. This can be used to check if functions are available in the current version. Can also be used to check if there is even any implementation for WMI functionality, as these are not mandatory for compiling the openvas-scanner. By default the openvas-scanner implementation just returns a *NULL* value for all functionalities. In order to use WMI **[openvas-smb](https://github.com/greenbone/openvas-smb)** has to be installed before.

## RETURN VALUE

The current version of the WMI implementation as *string* or *NULL* if there is none.
