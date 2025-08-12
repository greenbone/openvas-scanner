# table_driven_lsc

## NAME

**notus_error** - Get the last notus error as string

## SYNOPSIS

*str* **notus**();

**notus** takes no arguments

## DESCRIPTION

This function yields the last occurred error produced by the **[notus(3)](notus.md)** function.

## RETURN VALUE

This function returns a error message as string

## EXAMPLE

**1** Run a manual table driven lsc and publish results:
```cpp
package_list = 'libzmq3-dev-0:4.3.0-4+deb10u1\nlibzmq5-4.3.1-4+deb10u1\ndosbox-0.74-2-3+deb10u1';
product = "debian_10";

ret = notus(pkg_list: package_list, product: product);

if (!ret)
{
    display(notus_error());
}
```

## SEE ALSO

**[notus(3)](notus.md)**
