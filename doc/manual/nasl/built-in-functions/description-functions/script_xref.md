# script_xref

## NAME

**script_xref** - Add a cross reference to the meta data.

## SYNOPSIS

*any* **script_xref**(*string*);

**script xref**  takes one named string argument (name: "URL", value:LINK")

## DESCRIPTION

The parameter "name" of the command defines actually the type, for example "URL" or "OSVDB".
The parameter "value" is the actual reference. Alternative to "value", "csv" can be used with a list of comma-separated values. 

In fact, if name is "cve", it is equivalent to call script_cve_id(), 
This even works with multiple comma-separated elements like
script_xref (name: "cve", csv: "CVE-2019-12345,CVE-2019-54321");


## RETURN VALUE

Returns nothing.

## ERRORS
- If name is empty.
- If no value and no cve
 
## EXAMPLES

**1**: 
```cpp
script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1545");
```

**2**:
```cpp
//if name is "cve" is identical to call script_cve_id()
script_xref (name: "cve", value: "CVE-2019-12345");
```

**3**:
```cpp
//This even works with multiple comma-separated elements like
script_xref (name: "cve", csv: "CVE-2019-12345,CVE-2019-54321");
```


## SEE ALSO

**[script_add_preference(3)](script_add_preference.md)**, **[script_copyright(3)](script_copyright.md)**, **[script_cve_id(3)](script_cve_id.md)**, **[script_dependencies(3)](script_dependencies.md)**, **[script_exclude_keys(3)](script_exclude_keys.md)**, **[script_mandatory_keys(3)](script_mandatory_keys.md)**, **[script_category(3)](script_category.md)**, **[script_family(3)](script_family.md)**, **[script_name(3)](script_name.md)**, **[script_require_keys(3)](script_require_keys.md)**, **[script_require_ports(3)](script_require_ports.md)**, **[script_require_udp_ports(3)](script_require_udp_ports.md)**, **[script_timeout(3)](script_timeout.md)**, **[script_oid(3)](script_oid.md)**, **[script_version(3)](script_version.md)**, **[script_tag(3)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
