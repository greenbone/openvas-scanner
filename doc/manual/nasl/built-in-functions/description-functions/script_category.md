# script_category(3nasl)

## NAME

**script_category** - sets the plugin's category.

## SYNOPSIS

*any* **script_category**(*string*);

**script category** It takes one unnamed value.

## DESCRIPTION

Sets the plugin's category. The valid categories are the following:

- ACT_INIT
- ACT_SCANNER
- ACT_SETTINGS
- ACT_GATHER_INFO
- ACT_ATTACK
- ACT_MIXED_ATTACK
- ACT_DESTRUCTIVE_ATTACK
- ACT_DENIAL
- ACT_KILL_HOST
- ACT_FLOOD
- ACT_END

## RETURN VALUE

Returns nothing.

## ERRORS

 
## EXAMPLES

**1**: 
```cpp
script_category(<category>);

```

## SEE ALSO

**[script_add_preference(3nasl)](script_add_preference.md)**, **[script_copyright(3nasl)](script_copyright.md)**, **[script_cve_id(3nasl)](script_cve_id.md)**, **[script_dependencies(3nasl)](script_dependencies.md)**, **[script_exclude_keys(3nasl)](script_exclude_keys.md)**, **[script_mandatory_keys(3nasl)](script_mandatory_keys.md)**, **[script_family(3nasl)](script_family.md)**, **[script_oid(3nasl)](script_oid.md)**, **[script_name(3nasl)](script_name.md)**, **[script_require_keys(3nasl)](script_require_keys.md)**, **[script_require_ports(3nasl)](script_require_ports.md)**, **[script_require_udp_ports(3nasl)](script_require_udp_ports.md)**, **[script_timeout(3nasl)](script_timeout.md)**, **[script_version(3nasl)](script_version.md)**, **[script_xref(3nasl)](script_xref.md)**, **[script_tag(3nasl)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
