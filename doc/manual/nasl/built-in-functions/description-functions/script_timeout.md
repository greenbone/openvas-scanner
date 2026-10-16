# script_timeout(3nasl)

## NAME

**script_timeout** - sets the default timeout of the plugin.

## SYNOPSIS

*any* **script_timeout**(*int*);

**script timeout**  It takes an unnamed integer argument. If it is 0 or (-1), the timeout is infinite.sets the plugin's timeout.


## DESCRIPTION

sets the default timeout of the plugin. It takes an unnamed integer argument. If it is 0 or (-1), the timeout is infinite.
It is stored in redis as a plugin preference with the reserved preference ID 0.

## RETURN VALUE

Returns nothing.

## ERRORS

 
## EXAMPLES

**1**: 
```cpp
script_timeout(320);
```

## SEE ALSO

**[script_add_preference(3nasl)](script_add_preference.md)**, **[script_copyright(3nasl)](script_copyright.md)**, **[script_cve_id(3nasl)](script_cve_id.md)**, **[script_dependencies(3nasl)](script_dependencies.md)**, **[script_exclude_keys(3nasl)](script_exclude_keys.md)**, **[script_mandatory_keys(3nasl)](script_mandatory_keys.md)**, **[script_category(3nasl)](script_category.md)**, **[script_family(3nasl)](script_family.md)**, **[script_name(3nasl)](script_name.md)**, **[script_require_keys(3nasl)](script_require_keys.md)**, **[script_require_ports(3nasl)](script_require_ports.md)**, **[script_require_udp_ports(3nasl)](script_require_udp_ports.md)**, **[script_oid(3nasl)](script_oid.md)**, **[script_version(3nasl)](script_version.md)**, **[script_xref(3nasl)](script_xref.md)**, **[script_tag(3nasl)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
