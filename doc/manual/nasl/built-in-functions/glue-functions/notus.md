# notus

## NAME

**notus** - Starts a notus scan with given data

## SYNOPSIS

*array* **notus**(pkg_list: *str*, product: *str*);

**notus** two named arguments

## DESCRIPTION

This function takes the given information and starts a notus scan. Its arguments are:
pkg_list: comma separated list of installed packages of the target system
product: identifier for the notus scanner to get list of vulnerable packages

In contrast to **[update_table_driven_lsc_data(3)](update_table_driven_lsc_data.md)**
this function does not publish results by itself, but returns a json like structure,
so information can be adjusted and must be published using
**[security_notus(3)](../report-functions/security_notus.md)**. The json like format depends
one the scanner that is used. There are currently 2 scanner types available: Notus and
Skiron. Their response have different formats and also will be parsed differently. The
format for Notus has the following structure:
```json
[
  0: {
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
  1: {
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
The root element is a list of results.
The elements can be accessed by using the normal NASL array handling. For more information see the example.

The format for Skiron has the following structure:
```json
[
  {
    "oid": "[oid1]",
    "message": "[message1]"
  },
  {
    "oid": "[oid2]",
    "message": "[message2]"
  }
]
```
It is a list of dictionaries. Each dictionary has the key `oid` and `message`.

To determine which format is used, the builtin function **[notus_type(3)](notus_type.md)** can be used.

In case of an Error a NULL value is returned and an Error is set. The error can be gathered using the
**[notus_error(3)](notus_error.md)** function, which yields the last occurred error.

## RETURN VALUE

This function returns an array of notus results

## ERRORS

Possible errors

- Missing function parameter
- Unable to get result from Notus
- Error while parsing Notus results
- Unable to parse response

## EXAMPLE

**1** Run a manual table driven lsc and publish results:
```cpp
package_list = 'libzmq3-dev-0:4.3.0-4+deb10u1\nlibzmq5-4.3.1-4+deb10u1\ndosbox-0.74-2-3+deb10u1';
product = "debian_10";

ret = notus(pkg_list: package_list, product: product);

foreach result (ret)
{
  security_notus(result: result);
}
```

**2** Run a manual table driven lsc and access result fields:
```cpp
package_list = 'libzmq3-dev-0:4.3.0-4+deb10u1\nlibzmq5-4.3.1-4+deb10u1\ndosbox-0.74-2-3+deb10u1';
product = "debian_10";

ret = notus(pkg_list: package_list, product: product);
type = notus_type();

if (type == 0) {
  foreach result (ret)
  {
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
} else if (type == 1) {
  foreach result (ret)
  {
    oid = result["oid"];
    message = result["message"]
  }
}
```


## SEE ALSO

**[update_table_driven_lsc_data(3)](update_table_driven_lsc_data.md)**, **[security_notus(3)](../report-functions/security_notus.md)**, **[notus_error(3)](notus_error.md)**, **[notus_type(3)](notus_type.md)**
