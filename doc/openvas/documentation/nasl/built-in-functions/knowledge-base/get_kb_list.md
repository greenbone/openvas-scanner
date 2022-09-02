# get_kb_list

## NAME

**get_kb_list** - retrieves multiple entries from the KB

## SYNOPSIS

*any* **get_kb_list**(0: *string*);

**get_kb_item** takes 1 positional argument.


## DESCRIPTION

This function is used to retrieve entries from the KB in a list. It is mainly used for inter-plugin communication, so data can be transferred between scripts.

The first positional argument determines the name of the entry, which should be retrieved. Alternatively a mask can be given to match multiple KB entries


## RETURN VALUE

KB items as a list of key-value pairs or None if array size is 0

## ERRORS

first positional argument is not given

## EXAMPLES

**1**: Create an entry, which expires after 10 minutes
```cpp
set_kb_item(name: "hosts", value: "foo");
set_kb_item(name: "hosts", value: "bar");

display(get_kb_list("abc"));
# should print [ hosts: 'bar', hosts: 'foo', boo: 'baz' ]
```

**2**: Create an entry, which does not expire
```cpp
set_kb_item(name: "age", value: "42");
```


**3**: Create a list
```cpp
set_kb_item(name: "hosts", value: "foo");
set_kb_item(name: "hosts", value: "bar");
```

## SEE ALSO

[set_kb_item](set_kb_item.md), [get_kb_item](get_kb_ite.md), [replace_kb_item](replace_kb_item.md), [get_host_kb_index](get_host_kb_idex.md), [openvas-nasl](../../openvas-nasl.md)