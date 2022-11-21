# Description Functions

## GENERAL

All those functions but script_get_preference are only used in the "description part" of the plugin, i.e. the block that is run when the description variable is 1. They have no effect when the plugin is run with the standalone NASL interpreter.


## TABLE OF CONTENT

**script_add_preference** - Adds an option to the plugin.
**script_bugtraq_id** - Removed. Sets the SecurityFocus “bid”.
**script_category sets** - The “category” of the plugin.
**script_copyright** - Deprecated. Kept for backward compatibility. Sets the copyright string of the plugin.
**script_cve_id** - sets the CVE IDs of the flaws tested by the script.
**script_dependencies** - Sets the lists of scripts that should be run before this one (if “optimize mode” is on).
**script_exclude_keys** - sets the list of “KB items” that must not be set to run this script in “optimize mode”.
**script_mandatory_keys** - sets the list of “KB items” that must be set to run this script.
**script_family** - sets the “family” of the plugin. It takes an unnamed string argument.
**script_oid** - sets the script number.
**script_name** - sets the “name” of the plugin.
**script_require_keys** - sets the list of “KB items” that must be set to run this script.
**script_require_ports** - sets the list of TCP ports that must be open to run this script in “optimize mode”.
**script_require_udp_ports** - sets the list of UDP ports that must be open to run this script in “optimize mode”.
**script_timeout** - sets the default timeout of the plugin.
**script_version** - sets the “version” of the plugin.
**script_xref** - URLs related to the script.
**script_tag** - sets additional information.
