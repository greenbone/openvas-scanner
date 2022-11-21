# script_tag

## NAME

**script_tag** - sets additional information. Takes a named string argument:

## SYNOPSIS

*any* **script_tag**(name: *string*, value: *string*);

**script tag** It takes two named arguments. The following are the supported tags:

- *last_modification* date and time the script was last modified (Format: YYYY-MM-DD HH:mm:ss +0000 (Sat, 14 Oct YYYY))
- *creation_date* date and time the script was created (Format: YYYY-MM-DD HH:mm:ss +0000 (Sat, 14 Oct YYYY))
- *severity_vector* CVSSv3 vector if available, CVSSv2 otherwise (Added with GVM-21.04. No effect on previous versions)
- *severity_origin* the origin of the CVSS vector. Possible values: (Added with GVM-21.04. No effect on previous versions)
  - NVD: if a CVE is the source
  - Vendor: if a vendor like Red Hat, Ubuntu, Cisco etc. is the source
  - Third Party: if a researcher, blog post , Vulnerability Reporter etc. is the source
  - Greenbone: if we added the CVSSv3 vector by ourselves without a source. (Note: If one or more CVEs are assigned to a VT but there was no CVSS score assessment of the NVD done yet one of the other possibilities should be used depending on the origin of the score.)
- severity_date the date the CVSS vector was last modified. Format: LC_ALL=C date -u +"%F %T %z (%a, %d %b %Y)" (Added with GVM-21.04. No effect on previous versions)
- cvss_base the CVSS computed from the cvss_base_vector
- cvss_base_vector The CVSSv2 base vector
- qod_type one of the following Quality of Detection types. If the type is not valid, a default (70%) is set. (Please note: Please either assign a QoD type OR alternatively a QoD value, NOT both):
  - exploit (qod: 100%): The detection happened via an exploit and is therefore fully verified.
  - remote_vul (99%): Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response clearly shows the presence of the vulnerability.
  - remote_app (98%): Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response clearly shows the presence of the vulnerable application.
  - package (97%): Authenticated package-based checks for Linux(oid) systems.
  - registry (97%): Authenticated registry based checks for Windows systems.
  - remote_active (95%): Remote active checks (code execution, traversal attack, SQL injection etc.) in which the response shows the likely presence of the vulnerable application or of the vulnerability. “Likely” means that only rare circumstances are possible in which the detection would be wrong.
  - remote_banner (80%): Remote banner check of applications that offer patch level in version. Many proprietary products do so.
  - executable_version (80%): Authenticated executable version checks for Linux(oid) or Windows systems where applications offer patch level in version.
  - remote_analysis (70%): Remote checks that do some analysis but which are not always fully reliable.
  - remote_probe (50%): Remote checks in which intermediate systems such as firewalls might pretend correct detection so that it is actually not clear whether the application itself answered. For example, this can happen for non-TLS connections.
  - remote_banner_unreliable (30%): Remote banner checks of applications that do not offer patch level in version identification. For example, this is the case for many open source products due to backport patches.
  - executable_version_unreliable (30%): Authenticated executable version checks for Linux(oid) systems where applications do not offer patch level in version identification.
  - general_note (1%): General note on potential vulnerability without finding any present application.
- qod one of the above percentage values as string (Please note: Please either assign a QoD type OR alternatively a QoD value, NOT both)
- solution_type This information shows possible solutions for the remediation of the vulnerability:
  - Workaround Information about a configuration or specific deployment scenario that can be used to avoid exposure to the vulnerability is available. There can be none, one or more workarounds available. This is usually the “first line of defense” against a new vulnerability before a mitigation or vendor fix has been issued or even discovered.
  - Mitigation Information about a configuration or deployment scenario that helps to reduce the risk of the vulnerability is available but that does not resolve the vulnerability on the affected product. Mitigations may include using devices or access controls external to the affected product. Mitigations may or may not be issued by the original author of the affected product and they may or may not be officially sanctioned by the document producer.
  - Vendor fix Information is available about an official fix that is issued by the original author of the affected product. Unless otherwise noted, it is assumed that this fix fully resolves the vulnerability.
  - No fix available Currently there is no fix available. Information should contain details about why there is no fix.
  - Will not fix There is no fix for the vulnerability and there never will be one. This is often the case when a product has been orphaned, is no longer maintained or otherwise deprecated. Information should contain details about why there will be no fix issued.
- summary Description of the vulnerability test (e.g.: "softwareXYZ is prone to multiple vulnerabilities."). This tag is mandatory!
- vuldetect Description on the method used to detect the vulnerability (e.g.: "Checks if a vulnerable version is present on the target host.")
- insight Some more details about the vulnerability (e.g.: "The flaw exists due to a buffer over-read error in the 'foo' function in path/to/file script."),
- impact Details about the impact of the vulnerability (e.g.: "Successful exploitation allows an attacker to obtain sensitive information.")
- affected Information about affected versions / software (e.g.: "SoftwareXYZ 1.3.7 and prior.")
- solution Details how to remediate the vulnerability (e.g.: "Update to version 1.3.8 or later.")

## DESCRIPTION

Sets additional information. The severity tags can be used just once.


## RETURN VALUE

Returns nothing.

## ERRORS

 
## EXAMPLES

**1**: 
```cpp
script_tag(name:"summary", value:"The remote host is missing one or more known mitigation(s) on Linux Kernel side for the referenced 'Meltdown' hardware vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks previous gathered information on the mitigation status reported by the Linux Kernel.");

  script_tag(name:"solution", value:"Enable the mitigation(s) in the Linux Kernel or update to a more recent Linux Kernel.");

  script_tag(name:"qod", value:"80");
  script_tag(name:"solution_type", value:"VendorFix");
```

## SEE ALSO

**[script_add_preference(3)](script_add_preference.md)**, **[script_copyright(3)](script_copyright.md)**, **[script_cve_id(3)](script_cve_id.md)**, **[script_dependencies(3)](script_dependencies.md)**, **[script_exclude_keys(3)](script_exclude_keys.md)**, **[script_mandatory_keys(3)](script_mandatory_keys.md)**, **[script_category(3)](script_category.md)**, **[script_family(3)](script_family.md)**, **[script_name(3)](script_name.md)**, **[script_require_keys(3)](script_require_keys.md)**, **[script_require_ports(3)](script_require_ports.md)**, **[script_require_udp_ports(3)](script_require_udp_ports.md)**, **[script_timeout(3)](script_timeout.md)**, **[script_version(3)](script_version.md)**, **[script_xref(3)](script_xref.md)**, **[script_oid(3)](script_oid.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
