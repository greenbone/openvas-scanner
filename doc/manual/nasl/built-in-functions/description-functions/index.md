# Description Functions

## GENERAL

All those functions but script_get_preference are only used in the "description part" of the plugin, i.e. the block that is run when the description variable is 1. They have no effect when the plugin is run with the standalone NASL interpreter.


## TABLE OF CONTENT

- **[script_add_preference](script_add_preference.md)** - adds an option to the plugin. 
- **[script_category](script_category.md)** - sets the plugin's category.
- **[script_copyright](script_copyright.md)** - Deprecated. Kept for backward compatibility, but currently does nothing.
- **[script_cve_id](script_cve_id.md)** - sets the CVE IDs of the flaws tested by the script. 
- **[script_dependencies](script_dependencies.md)** - sets the lists of scripts that should be run before this one (if “optimize mode” is on). 
- **[script_exclude_keys](script_exclude_keys.md)** - sets the list of “KB items” that must not be set to run this script in “optimize mode”. 
- **[script_family](script_family.md)** - sets the plugin's family.
- **[script_mandatory_keys](script_mandatory_keys.md)** - sets the list of “KB items” that must be set to run this script.
- **[script_name](script_name.md)** - sets the plugin's name.
- **[script_oid](script_oid.md)** - sets the plugin's oid.
- **[script_require_keys](script_require_keys.md)** - sets the list of “KB items” that must be set to run this script.
- **[script_require_ports](script_require_ports.md)** - sets the list of TCP ports that must be open to run this script in “optimize mode”.
- **[script_require_udp_ports](script_require_udp_ports.md)** - sets the list of UDP ports that must be open to run this script in “optimize mode”.
- **[script_tag](script_tag.md)** - sets additional information. Takes a named string argument:
- **[script_timeout](script_timeout.md)** - sets the default timeout of the plugin.
- **[script_version](script_version.md)** - sets the plugin's version.
- **[script_xref](script_xref.md)** - Add a cross reference to the meta data.
