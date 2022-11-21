# script_dependencies

## NAME

**script_dependencies** - sets the lists of scripts that should be run before this one (if “optimize mode” is on). 

## SYNOPSIS

*any* **script_dependencies**(*string*, ...);

**script dependencies** It takes any number of unnamed string arguments.

## DESCRIPTION

Sets the plugin's dependencies. Sets the lists of scripts that should be run before this one (if “optimize mode” is on). 

## RETURN VALUE

Returns nothing.

## ERRORS

It requires at least one string as argument.
 
## EXAMPLES

**1**: 
```cpp
 script_dependencies("toolcheck.nasl", "host_alive_detection.nasl");

```

## SEE ALSO

**[script_add_preference(3)](script_add_preference.md)**, **[script_copyright(3)](script_copyright.md)**, **[script_cve_id(3)](script_cve_id.md)**, **[script_category(3)](script_dependencies.md)**, **[script_exclude_keys(3)](script_exclude_keys.md)**, **[script_mandatory_keys(3)](script_mandatory_keys.md)**, **[script_family(3)](script_family.md)**, **[script_oid(3)](script_oid.md)**, **[script_name(3)](script_name.md)**, **[script_require_keys(3)](script_require_keys.md)**, **[script_require_ports(3)](script_require_ports.md)**, **[script_require_udp_ports(3)](script_require_udp_ports.md)**, **[script_timeout(3)](script_timeout.md)**, **[script_version(3)](script_version.md)**, **[script_xref(3)](script_xref.md)**, **[script_tag(3)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
