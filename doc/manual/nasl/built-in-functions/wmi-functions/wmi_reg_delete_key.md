# wmi_reg_delete_key

## NAME

**wmi_reg_delete_key** - delete a key in the registry

## SYNOPSIS

*bool* **wmi_reg_delete_key**(wmi_handle: *int*, key: *string*);

**wmi_reg_delete_key** takes 2 named arguments.

## DESCRIPTION

This function deletes a key in the registry.

The named argument *wmi_handle* is an *int* representing a connection to a WMI server. This connection can be opened with on of the **[wmi_connect(3)](wmi_connect.md)** functions.

The named argument *key* is a *string* containing the key to delete.

## RETURN VALUE

*TRUE* und success, *FALSE* on failure.

## SEE ALSO

**[wmi_connect(3)](wmi_connect.md)**
