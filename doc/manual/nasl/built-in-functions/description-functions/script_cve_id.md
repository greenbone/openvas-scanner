# script_cve_id

## NAME

**script_cve_id** - sets the CVE IDs of the flaws tested by the script. 

## SYNOPSIS

*any* **script_cve_id**(*string*, *string*, ...);

**script cve id** It takes any number of unnamed string arguments. They usually looks like "CVE-2002-042".

## DESCRIPTION
Sets the CVE IDs of the flaws tested by the script. It takes any number of unnamed string arguments. They usually looks like "CVE-2002-042".
The CVEs are stored as NVT references.

## RETURN VALUE

Returns nothing.

## ERRORS

 
## EXAMPLES

**1**: 
```cpp
script_cve_id("CVE-2016-8650", "CVE-2016-9793", "CVE-2017-2618", "CVE-2017-2636");

```

## SEE ALSO

**[script_add_preference(3)](script_add_preference.md)**, **[script_copyright(3)](script_copyright.md)**, **[script_category(3)](script_category.md)**, **[script_dependencies(3)](script_dependencies.md)**, **[script_exclude_keys(3)](script_exclude_keys.md)**, **[script_mandatory_keys(3)](script_mandatory_keys.md)**, **[script_family(3)](script_family.md)**, **[script_oid(3)](script_oid.md)**, **[script_name(3)](script_name.md)**, **[script_require_keys(3)](script_require_keys.md)**, **[script_require_ports(3)](script_require_ports.md)**, **[script_require_udp_ports(3)](script_require_udp_ports.md)**, **[script_timeout(3)](script_timeout.md)**, **[script_version(3)](script_version.md)**, **[script_xref(3)](script_xref.md)**, **[script_tag(3)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
