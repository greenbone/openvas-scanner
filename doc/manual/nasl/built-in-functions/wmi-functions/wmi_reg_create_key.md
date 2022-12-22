# wmi_reg_create_key

## NAME

**wmi_reg_create_key** - create registry key

## SYNOPSIS

*bool* **wmi_reg_create_key**(wmi_handle: *int*, key: *string*);

**wmi_reg_create_key** takes two named arguments.

## DESCRIPTION

This functions creates a new key in the registry.

The named argument *wmi_handle* is an *int* representing a connection to a WMI server. This connection can be opened with on of the **[wmi_connect(3)](wmi_connect.md)** functions.

The named argument *key* is a *string* containing the new key to create.

## RETURN VALUE

*TRUE* on success, *FALSE* on failure

## SEE ALSO

**[wmi_connect(3)](wmi_connect.md)**
