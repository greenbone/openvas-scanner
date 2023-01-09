# wmi_query

## NAME

**wmi_query** - perform a WQL query

## SYNOPSIS

*string* **wmi_query**(wmi_handle: *int*, query: *string*);
*string* **wmi_query_rsop**(wmi_handle: *int*, query: *string*);

## DESCRIPTION

This function takes a wmi handle and performs a WQL query on it. WQL is the WMI Query Language.

The named argument *wmi_handle* is an *int* representing a connection to a WMI server. This connection can be opened with on of the **[wmi_connect(3)](wmi_connect.md)** functions.

The named argument *query* is a *string* containing the query to perform.

## RETURN VALUE

The result of the query as *string*, *NULL* on error.

## ERRORS

The named argument *wmi_handle* is missing

Unable to run query

## SEE ALSO

**[wmi_connect(3)](wmi_connect.md)**
