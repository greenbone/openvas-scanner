# get_kb_list

## NAME

**get_kb_list** - retrieves multiple entries from the KB

## SYNOPSIS

*any* **get_kb_list**(0: *string*);

**get_kb_list** takes 1 positional argument.


## DESCRIPTION

This function is used to retrieve entries from the KB in a list. It is mainly used for inter-plugin communication, so data can be transferred between scripts.

The first positional argument determines the name of the entry, which should be retrieved. Alternatively a mask can be given to match multiple KB entries


## RETURN VALUE

KB items as a list of key-value pairs or None if array size is 0

## ERRORS

first positional argument is not given

## EXAMPLES

**1**: Create a list with expiring keys and display it
```cpp
set_kb_item(name: "hosts", value: "foo", expire: 600);
set_kb_item(name: "hosts", value: "bar", expire: 600);

display(get_kb_list("hosts"));
# should print [ hosts: 'foo', boo: 'baz' ]
```

## SEE ALSO

**[set_kb_item(3)](set_kb_item.md)**, **[get_kb_item(3)](get_kb_item.md)**, **[replace_kb_item(3)](replace_kb_item.md)**, **[get_host_kb_index(3)](get_host_kb_index.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
