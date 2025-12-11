# notus_type

## NAME

**notus_type** - Get the type of the notus result

## SYNOPSIS

*str* **notus_type**();

**notus_type** takes no arguments

## DESCRIPTION

This function yields the type of the notus result after calling the **[notus(3)](notus.md)** function.

## RETURN VALUE

0 for Notus, 1 for Skiron

## EXAMPLE

**1** Run a manual table driven lsc and publish results:
```cpp
package_list = 'libzmq3-dev-0:4.3.0-4+deb10u1\nlibzmq5-4.3.1-4+deb10u1\ndosbox-0.74-2-3+deb10u1';
product = "debian_10";

ret = notus(pkg_list: package_list, product: product);
type = notus_type();

if (type == 0)
{
    ...
} else if (type == 1) {
    ...
}
```

## SEE ALSO

**[notus(3)](notus.md)**
