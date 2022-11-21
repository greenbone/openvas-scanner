# script_add_preference

## NAME

**script_add_preference** - adds an option to the plugin. 

## SYNOPSIS

*any* **script_add_preference**(name: *string*, type: *string*, value: *string*, id: *int*);

**script_add_preference** It takes four named arguments.
- **name** is the option name. As it is displayed “as is” in the GUI, it usually ends with “:”. Despite since GVM 11 (openvas-scanner-7) the VT preferences are ID based, it is not possible to drop the name, since it is use in the GUI, as already mentioned. Also, until versions older than GVM 11 reach the end of life, the preference name can not be modified, since in those older version the preferences are still name-based.

- **type** is the option type. It may be: *checkbox, entry, password, radio*

- **value** is the default value (“yes” or “no” for "checkbox", a text string for “entry” or “password”) except for “radio”, where it is the list of options (separate the items with “;”). e.g.
    script_add_preference(name:"Reverse traversal", type:"radio", value:"none;Basic;Long URL", id:1);

- **id** is the id for that preference.
  - Should not be modified once existing!
  - The scanner detects if the id is repeated. If a preference does not have an ID and the following line adds a preferences with the ID = 1, the scanner will log a messages. This is because an ID will be assigned automatically for the first preference without ID (assign id = 1). The second preferences tries to add a new entry with the id 1, which is already in use, but it is not possible. Therefore is very important to preserve the order of the preferences once they have been added without an id.
  - Do not use ID 0. The scanner detects if the id 0 is being used, which is invalid because id 0 is reserved for the timeout preference.
  - The scanner detects if an ID has a non-integer value. An error messages is shown in the log
  - The preference id should always stay the same. One of the reasons for introducing the id was ensuring that configs will refer to the correct preference even if the preference name is changed (e.g. to fix a typo).
  - Removing preferences, and especially reusing the ids should be avoided because they are not removed from scan configs, which could result in an inconsistent state if the id is reused for something different.
  - For preference without ID, the assigned ID is the position number in the preference list. If the order is changed, it is as removing the preference and adding a new one reusing the ID, which could result in an inconsistent state.


## DESCRIPTION

This function adds plugin preference to the plugin.

## RETURN VALUE

KB items as a list of key-value pairs or None if array size is 0

## ERRORS

 - Invalid id or not allowed id value. ID must be greather than 0. 
 - Argument error in the call to script_add_preference. No name nor type neither value.
 - Preference already exists.
 
## EXAMPLES

**1**: 
```cpp
script_add_preference(name:"Service scan", type:"checkbox", value:"no", id:2);

```

## SEE ALSO

**[script_bugtraq_id(3)](script_bugtraq_id.md)**, **[script_category(3)](script_category.md)**, **[script_copyright(3)](script_copyright.md)**, **[script_cve_id(3)](script_cve_id.md)**, **[script_dependencies(3)](script_dependencies.md)**, **[script_exclude_keys(3)](script_exclude_keys.md)**, **[script_mandatory_keys(3)](script_mandatory_keys.md)**, **[script_family(3)](script_family.md)**, **[script_oid(3)](script_oid.md)**, **[script_name(3)](script_name.md)**, **[script_require_keys(3)](script_require_keys.md)**, **[script_require_ports(3)](script_require_ports.md)**, **[script_require_udp_ports(3)](script_require_udp_ports.md)**, **[script_timeout(3)](script_timeout.md)**, **[script_version(3)](script_version.md)**, **[script_xref(3)](script_xref.md)**, **[script_tag(3)](script_tag.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
