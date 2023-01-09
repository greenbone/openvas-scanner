# wmi_close

## NAME

**wmi_close** - closes an opened WMI handle

## SYNOPSIS

*bool* **wmi_close**(wmi_handle: *int*);

**wmi_close** takes one named argument

## DESCRIPTION

This function closes a before opened WMI handle. A WMI handle can be opened with **[wmi_connect(3)](wmi_connect.md)**.

The named *wmi_handle* argument is a *int* containing a representation of a WMI handle.

## RETURN VALUE

*TRUE* on success, *NULL* on failure or error.

## ERRORS

The named argument *wmi_handle* is missing or 0.

## SEE ALSO

**[wmi_connect(3)](wmi_connect.md)**
