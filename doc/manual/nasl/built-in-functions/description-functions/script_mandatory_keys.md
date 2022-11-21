# script_mandatory_keys

## NAME

**script_mandatory_keys** - sets the list of “KB items” that must be set to run this script.

## SYNOPSIS

*any* **script_mandatory_keys**(*string*, ..., re: *string*);

**script mandatory_keys** takes any number of unnamed string arguments. Additionally it takes an optional named string argument re. With this option a specific required key has to contain a value defined with a regular expression. The re argument has to follow the specific pattern: re: '<name>=<regex>'.

## DESCRIPTION

Sets the list of “KB items” that must be set to run this script.

## RETURN VALUE

Returns nothing.

## ERRORS

 
## EXAMPLES

**1**: 
```cpp
script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
```

## SEE ALSO

**[script_add_preference(3)](script_add_preference.md)**, **[script_copyright(3)](script_copyright.md)**, **[script_cve_id(3)](script_cve_id.md)**, **[script_dependencies(3)](script_dependencies.md)**, **[script_category(3)](script_category.md)**, **[script_exclude_keys(3)](script_mandatory_keys.md)**, **[script_family(3)](script_family.md)**, **[script_oid(3)](script_oid.md)**, **[script_name(3)](script_name.md)**, **[script_require_keys(3)](script_require_keys.md)**, **[script_require_ports(3)](script_require_ports.md)**, **[script_require_udp_ports(3)](script_require_udp_ports.md)**, **[script_timeout(3)](script_timeout.md)**, **[script_version(3)](script_version.md)**, **[script_xref(3)](script_xref.md)**, **[script_tag(3)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
