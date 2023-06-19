# Extends nasl-function that don't have network or file capabilities

It is part of the std which is proven in the tests.

To use this module you have to initiate `Description` and look for the function:

```
let functions = nasl_builtin_utils::NaslfunctionRegisterBuilder::new()
    .push_register(nasl_builtin_description::Description)
    .build();
```

## Implements

- script_timeout
- script_category
- script_name
- script_version
- script_copyright
- script_family
- script_oid
- script_dependencies
- script_exclude_keys
- script_mandatory_keys
- script_require_ports
- script_require_udp_ports
- script_require_keys
- script_cve_id
- script_tag
- script_xref
- script_add_preference
