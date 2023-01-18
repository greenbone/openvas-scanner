# WMI Functions

## GENERAL

Provides WMI (Windows Management Instrumentation) functionalities via calling functions of a appropriate library.
The API offers three groups of functions:
1. WMI_FUNCTIONS: run all-purpose queries
2. WMI_RSOP_FUNCTIONS (RSoP = Resultant Set of Policy): run RSoP queries
3. WMI_REGISTRY_FUNCTIONS: read and write values from/to the registry

In order to be able to use the WMI functions, **[openvas-smb](https://github.com/greenbone/openvas-smb)** has to be installed before.

## TABLE OF CONTENT

- **[wmi_close](wmi_close.md)** - closes an opened WMI handle
- **[wmi_connect](wmi_connect.md)** - Connect to a WMI service on the current target system
- **[wmi_connect_reg](wmi_connect_reg.md)** - Connect to a WMI service on the current target system to the registry namespace
- **[wmi_connect_rsop](wmi_connect_rsop.md)** - Connect to a WMI service on the current target system to the RSoP namespace
- **[wmi_query](wmi_query.md)** - perform a WQL query
- **[wmi_query_rsop](wmi_query_rsop.md)** - perform a WQL RSoP query
- **[wmi_reg_create_key](wmi_reg_create_key.md)** - create registry key
- **[wmi_reg_delete_key](wmi_reg_delete_key.md)** - delete a key in the registry
- **[wmi_reg_enum_key](wmi_reg_enum_key.md)** - enumerate registry keys
- **[wmi_reg_enum_value](wmi_reg_enum_value.md)** - enumerate registry values
- **[wmi_reg_get_bin_val](wmi_reg_get_bin_val.md)** - get registry binary value
- **[wmi_reg_get_dword_val](wmi_reg_get_dword_val.md)** - get dword registry value
- **[wmi_reg_get_ex_string_val](wmi_reg_get_ex_string_val.md)** - get a ex_string registry value
- **[wmi_reg_get_mul_string_val](wmi_reg_get_mul_string_val.md)** - get a mult_string registry value
- **[wmi_reg_get_qword_val](wmi_reg_get_qword_val.md)** - get a qword registry value
- **[wmi_reg_get_sz](wmi_reg_get_sz.md)** - get a sz registry value
- **[wmi_reg_set_dword_val](wmi_reg_set_dword_val.md)** - set a dword registry value
- **[wmi_reg_set_ex_string_val](wmi_reg_set_ex_string_val.md)** - set a ex_string registry value
- **[wmi_reg_set_qword_val](wmi_reg_set_qword_val.md)** - set a qword registry value
- **[wmi_reg_set_string_val](wmi_reg_set_string_val.md)** - set a string registry value
- **[wmi_versioninfo](wmi_versioninfo.md)** - get a version string of the WMI implementation
