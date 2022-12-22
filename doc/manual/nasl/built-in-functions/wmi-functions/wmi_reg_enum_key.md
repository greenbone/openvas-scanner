# wmi_reg_enum_key

## NAME

**wmi_reg_enum_key** - enumerate registry keys

## SYNOPSIS

*string* **wmi_reg_enum_key**(wmi_handle: *int*, hive: *int*, key: *string*);

**wmi_reg_enum_key** takes up to 3 positional arguments.

## DESCRIPTION

This function enumerates the registry keys.

The named argument *wmi_handle* is an *int* representing a connection to a WMI server. This connection can be opened with on of the **[wmi_connect(3)](wmi_connect.md)** functions.

The optional named argument *hive* is of type *int* and defines which registry hive is used. By default *HKEY_LOCALE_MACHINE* (*2147483650*) is used.

The named argument *key* is a *string* containing the registry key. This is the location of the keys to enumerate.

## RETURN VALUE

A *string* containing all keys.

## ERRORS

Missing or invalid *wmi_handle* argument.

Unable to run WMi query.

## SEE ALSO

**[wmi_connect(3)](wmi_connect.md)**
