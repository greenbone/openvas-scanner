# wmi_reg_get_ex_string_val

## NAME

**wmi_reg_get_ex_string_val** - get a ex_string registry value

## SYNOPSIS

*string* **wmi_reg_get_bin_val**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*string* **wmi_reg_get_dword_val**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*string* **wmi_reg_get_ex_string_val**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*string* **wmi_reg_get_mul_string_val**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*string* **wmi_reg_get_qword_val**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*string* **wmi_reg_get_sz**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*bool* **wmi_reg_set_dword_val**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*bool* **wmi_reg_set_ex_string_val**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*bool* **wmi_reg_set_qword_val**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);
*bool* **wmi_reg_set_string**(wmi_handle: *int*, hive: *int*, key: *string*, val_name: *string*);


## DESCRIPTION

All function described here get or set different values in the registry:
- bin: binary data in any form.
- dword: a 32-bit number
- qword: a 64-bit number
- ex_string: a null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%")
- mul_string: a sequence of null-terminated strings, terminated by an empty string (\0). The following is an example: String1\0String2\0String3\0LastString\0\0 The first \0 terminates the first string, the second to the last \0 terminates the last string, and the final \0 terminates the sequence. Note that the final terminator must be factored into the length of the string.
- sz/string: a null-terminated string

The named argument *wmi_handle* is an *int* representing a connection to a WMI server. This connection can be opened with on of the **[wmi_connect(3)](wmi_connect.md)** functions.

The optional named argument *hive* is of type *int* and defines which registry hive is used. By default *HKEY_LOCALE_MACHINE* (*2147483650*) is used.

The named argument *key* is a *string* containing the registry key. This is the location of the values to get or set.

The named argument *val_name* is a *string* containing the name of the value to set or get.

## RETURN VALUE

The set functions return a *bool*. *TRUE* on success, *FALSE* on failure or error.

The get functions return a *string* containing the desired value or *NULL* on failure or error.

## ERRORS

Missing or invalid *wmi_handle* argument.

Unable to run WMi query.

## SEE ALSO

**[wmi_connect(3)](wmi_connect.md)**
