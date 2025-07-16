# table_driven_lsc

## NAME

**table_driven_lsc** - Starts a notus scan with given data

## SYNOPSIS

*void* **table_driven_lsc**(pkg_list: *str*, product: *str*);

**table_driven_lsc** two named arguments

## DESCRIPTION

This function takes the given information and starts a notus scan. Its arguments are:
pkg_list: comma separated list of installed packages of the target system
product: identifier for the notus scanner to get list of vulnerable packages

In contrast to **[update_table_driven_lsc_data(3)](update_table_driven_lsc_data.md)**
this function does not publish results by itself, but returns a json like structure,
so information can be adjusted and must be published using
**[security_lsc(3)](../report-functions/security_lsc.md)**. The json like format has the
following structure:
```json
[
  0: [return code],
  1: {
    "oid": "[oid]",
    "vulnerable_packages": [{
      "name": "[package_name]",
      "installed": "[installed_version]",
      "fixed": {
        "version": "[fixed_version]",
        "specifier": "[specifier]"
      }
    }]
  },
  2: {
    "oid": "[oid]",
    "vulnerable_packages": [{
      "name": "[package_name]",
      "installed": "[installed_version]",
      "fixed": {
        "start": "[start_version]",
        "end": "[end_version]"
      }
    }]
  }
]
```
The root element is a list of results, where the first item is a return code for error handling.
The elements can be accessed by using the normal NASL array handling. For more information see the example.

## RETURN VALUE

This function returns nothing.

## EXAMPLE

**1** Run a manual table driven lsc and publish results:
```cpp
package_list = 'libzmq3-dev-0:4.3.0-4+deb10u1\nlibzmq5-4.3.1-4+deb10u1\ndosbox-0.74-2-3+deb10u1';
product = "debian_10";

ret = table_driven_lsc(pkg_list: package_list, product: product);

foreach result (ret)
{
  if(typeof(result) == "int") 
  {
    display("LSC return code: ", result);
    continue;
  }
  security_lsc(result: result);
}
```

**2** Run a manual table driven lsc and access result fields:
```cpp
package_list = 'libzmq3-dev-0:4.3.0-4+deb10u1\nlibzmq5-4.3.1-4+deb10u1\ndosbox-0.74-2-3+deb10u1';
product = "debian_10";

ret = table_driven_lsc(pkg_list: package_list, product: product);

foreach result (ret)
{
  if(typeof(result) == "int") 
  {
    display("LSC return code: ", result);
    continue;
  }
  oid = result["oid"];
  vul_packages = result["vulnerable_packages"];
  foreach package (vul_packages)
  {
    name = package["name"];
    installed = package["installed"];
    fixed = package["fixed"];
    fixed_version = fixed["version"];
    if (fixed_version.isnull()) {
        start = fixed["start"];
        end = fixed["end"];
    } else {
        specifier = fixed["specifier"];
    }
  }
}
```

## SEE ALSO

**[update_table_driven_lsc_data(3)](update_table_driven_lsc_data.md)**, **[security_lsc(3)](../report-functions/security_lsc.md)**