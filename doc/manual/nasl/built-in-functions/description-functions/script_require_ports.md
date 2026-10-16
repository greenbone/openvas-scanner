# script_require_ports(3nasl)

## REQUIRE_PORTS

**script_require_ports** - sets the list of TCP ports that must be open to run this script in “optimize mode”.

## SYNOPSIS

*any* **script_require_ports**(*string*, ..., *int*);

**script require_ports** It takes any number of unnamed integer or string arguments.

## DESCRIPTION

Sets the list of TCP ports that must be open to run this script in “optimize mode”.

Note: Please see the *non_simult_ports* option of [openvas(8)](../../../openvas/openvas.md) for some special handling of some ports.

## RETURN VALUE

Returns nothing.

## ERRORS

 
## EXAMPLES

**1**: 
```cpp
script_require_ports("Services/www", 443);
```

## SEE ALSO

**[script_add_preference(3nasl)](script_add_preference.md)**, **[script_copyright(3nasl)](script_copyright.md)**, **[script_cve_id(3nasl)](script_cve_id.md)**, **[script_dependencies(3nasl)](script_dependencies.md)**, **[script_exclude_keys(3nasl)](script_exclude_keys.md)**, **[script_mandatory_keys(3nasl)](script_mandatory_keys.md)**, **[script_category(3nasl)](script_category.md)**, **[script_family(3nasl)](script_family.md)**, **[script_oid(3nasl)](script_oid.md)**, **[script_name(3nasl)](script_name.md)**, **[script_require_keys(3nasl)](script_require_keys.md)**, **[script_require_udp_ports(3nasl)](script_require_udp_ports.md)**, **[script_timeout(3nasl)](script_timeout.md)**, **[script_version(3nasl)](script_version.md)**, **[script_xref(3nasl)](script_xref.md)**, **[script_tag(3nasl)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
