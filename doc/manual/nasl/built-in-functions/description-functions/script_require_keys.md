# script_require_keys(3nasl)

## REQUIRE_KEYS

**script_require_keys** - sets the list of “KB items” that must be set to run this script.

## SYNOPSIS

*any* **script_require_keys**(*string*, ...);

**script require_keys** It takes any number of unnamed string arguments.

## DESCRIPTION

Sets the list of “KB items” that must be set to run this script. This only applies if the option “optimize_test” is "yes". 

## RETURN VALUE

Returns nothing.

## ERRORS

 
## EXAMPLES

**1**: 
```cpp
script_require_keys("ftp/login");
```

## SEE ALSO

**[script_add_preference(3nasl)](script_add_preference.md)**, **[script_copyright(3nasl)](script_copyright.md)**, **[script_cve_id(3nasl)](script_cve_id.md)**, **[script_dependencies(3nasl)](script_dependencies.md)**, **[script_exclude_keys(3nasl)](script_exclude_keys.md)**, **[script_mandatory_keys(3nasl)](script_mandatory_keys.md)**, **[script_category(3nasl)](script_category.md)**, **[script_family(3nasl)](script_family.md)**, **[script_oid(3nasl)](script_oid.md)**, **[script_name(3nasl)](script_name.md)**, **[script_require_ports(3nasl)](script_require_ports.md)**, **[script_require_udp_ports(3nasl)](script_require_udp_ports.md)**, **[script_timeout(3nasl)](script_timeout.md)**, **[script_version(3nasl)](script_version.md)**, **[script_xref(3nasl)](script_xref.md)**, **[script_tag(3nasl)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
